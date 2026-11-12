#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sys/time.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <thread>
#include <vector>

namespace {

constexpr std::uint16_t kListenPort  = 5733;
constexpr std::uint16_t kForwardPort = 5744;

// Stream layout, worked out from the capture in Wireshark:
//
//   CTFS frame:  "CTFS" | seq (2, BE) | length (2, BE) | 8 unknown bytes | data[length]
//                └──────────────── 16-byte header ───────────────────┘
//
//   Other frame: Ethernet header (14) | IPv4 packet (IPv4 "total length" bytes)
constexpr std::size_t   kCtfsHeaderLen  = 16;
constexpr std::size_t   kCtfsSeqOffset  = 4;
constexpr std::size_t   kCtfsLenOffset  = 6;
constexpr std::uint8_t  kCtfsMagic[4]   = {'C', 'T', 'F', 'S'};

constexpr std::size_t   kEthHeaderLen     = 14;
constexpr std::size_t   kEthTypeOffset    = 12;
constexpr std::uint16_t kEthTypeIpv4      = 0x0800;
constexpr std::size_t   kIpv4MinHeaderLen = 20;
constexpr std::size_t   kIpv4TotalLenOffset = kEthHeaderLen + 2;

// Reads a 2-byte big-endian ("network order") number.
std::uint16_t read_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

enum class ParseStatus { NeedMore, Frame, Invalid };

struct FrameInfo {
    ParseStatus status;
    bool        is_ctfs;
    std::size_t length;   // whole frame, header included
};

// Looks at the start of `p` (with `avail` bytes buffered) and works out how
// long the next frame is. Returns NeedMore if the frame isn't fully buffered
// yet, so the caller can wait for the next recv() — TCP may split a frame
// across reads or pack several frames into one.
FrameInfo next_frame(const std::uint8_t* p, std::size_t avail) {
    constexpr FrameInfo kNeedMore{ParseStatus::NeedMore, false, 0};
    constexpr FrameInfo kInvalid{ParseStatus::Invalid, false, 0};

    if (avail < sizeof kCtfsMagic) return kNeedMore;

    if (std::memcmp(p, kCtfsMagic, sizeof kCtfsMagic) == 0) {
        if (avail < kCtfsHeaderLen) return kNeedMore;
        std::size_t len = kCtfsHeaderLen + read_be16(p + kCtfsLenOffset);
        if (avail < len) return kNeedMore;
        return {ParseStatus::Frame, true, len};
    }

    if (avail < kEthHeaderLen + kIpv4MinHeaderLen) return kNeedMore;
    if (read_be16(p + kEthTypeOffset) != kEthTypeIpv4) return kInvalid;

    std::size_t ip_len = read_be16(p + kIpv4TotalLenOffset);
    if (ip_len < kIpv4MinHeaderLen) return kInvalid;   // corrupt length: can't resync
    std::size_t len = kEthHeaderLen + ip_len;
    if (avail < len) return kNeedMore;
    return {ParseStatus::Frame, false, len};
}

// Collects CTFS payloads keyed by sequence number. std::map keeps its keys
// sorted, so packets that arrive out of order are put back in order for free.
class Reassembler {
public:
    // `frame` points at a whole CTFS frame of `length` bytes (header included).
    void add(const std::uint8_t* frame, std::size_t length) {
        std::uint16_t seq = read_be16(frame + kCtfsSeqOffset);
        const std::uint8_t* data = frame + kCtfsHeaderLen;
        // try_emplace does nothing if `seq` is already present, so a
        // retransmitted duplicate can't overwrite or double up the data.
        auto [it, inserted] = chunks_.try_emplace(seq, data, frame + length);
        if (!inserted) ++duplicates_;
    }

    // Writes the chunks in sequence order. Warns about any gaps rather than
    // failing, so a partial document is still saved for inspection.
    bool write(const char* path) const {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file) { std::perror(path); return false; }

        std::uint32_t expected = 0;
        for (const auto& [seq, data] : chunks_) {
            if (seq != expected)
                std::cerr << "warning: missing CTFS sequence " << expected
                          << " to " << (seq - 1) << '\n';
            file.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
            expected = std::uint32_t{seq} + 1;
        }
        return static_cast<bool>(file);
    }

    std::size_t chunk_count() const { return chunks_.size(); }
    std::size_t duplicates() const { return duplicates_; }

private:
    std::map<std::uint16_t, std::vector<std::uint8_t>> chunks_;
    std::size_t duplicates_ = 0;
};

// RAII: closes the file descriptor automatically when it goes out of scope.
class Socket {
public:
    explicit Socket(int fd = -1) : fd_(fd) {}
    ~Socket() { if (fd_ >= 0) ::close(fd_); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) {
            if (fd_ >= 0) ::close(fd_);
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
private:
    int fd_;
};

sockaddr_in make_addr(std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);                       // host -> network order
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    return addr;
}

Socket listen_on(std::uint16_t port) {
    Socket s(::socket(AF_INET, SOCK_STREAM, 0));
    if (!s.valid()) { std::perror("socket"); return Socket{}; }

    int yes = 1;
    ::setsockopt(s.get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    sockaddr_in addr = make_addr(port);
    if (::bind(s.get(), reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind"); return Socket{};
    }
    // Backlog > 1 so the real sender can queue while we deal with a stray connection.
    if (::listen(s.get(), 8) < 0) { std::perror("listen"); return Socket{}; }
    return s;
}

// Connects to the forward port, retrying briefly in case the receiver is
// still starting up.
Socket connect_to(std::uint16_t port) {
    constexpr int kAttempts = 20;
    constexpr auto kRetryDelay = std::chrono::milliseconds(100);
    sockaddr_in addr = make_addr(port);

    for (int attempt = 1;; ++attempt) {
        Socket s(::socket(AF_INET, SOCK_STREAM, 0));
        if (!s.valid()) { std::perror("socket"); return Socket{}; }
        if (::connect(s.get(), reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0) return s;
        if (errno != ECONNREFUSED || attempt == kAttempts) {
            std::perror("connect"); return Socket{};
        }
        std::this_thread::sleep_for(kRetryDelay);
    }
}

void set_recv_timeout(int fd, int seconds) {
    timeval tv{};
    tv.tv_sec = seconds;   // 0 = no timeout
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

// send() can write only part of the buffer, so keep going until it's all sent.
bool send_all(int fd, const std::uint8_t* data, std::size_t len) {
    while (len > 0) {
        ssize_t n = ::send(fd, data, len, MSG_NOSIGNAL);
        if (n < 0) { std::perror("send"); return false; }
        data += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

enum class SessionResult {
    Completed,   // handled a real FIRE STORM stream
    Rejected,    // not FIRE STORM traffic (browser, port probe...): ignore it
    Failed,      // real stream, but something broke part-way
};

// How long a new connection has to send its first valid frame. Browsers and
// port scanners often connect and send nothing, so we must not wait forever.
constexpr int kFirstFrameTimeoutSec = 2;

// Handles one incoming connection. The forward connection to :5744 is only
// opened once the first valid frame arrives, so a stray connection never
// touches the receiver.
SessionResult run_session(int in_fd) {
    constexpr std::size_t kReadSize = 64 * 1024;
    std::vector<std::uint8_t> pending;   // bytes received but not yet a whole frame
    std::vector<std::uint8_t> outbuf;    // frames to forward from this read
    std::size_t forwarded_frames = 0, forwarded_bytes = 0, ctfs_frames = 0;
    Reassembler document;
    Socket out;
    bool verified = false;               // seen at least one valid frame?

    set_recv_timeout(in_fd, kFirstFrameTimeoutSec);

    for (;;) {
        // recv() straight onto the end of `pending`, so no extra copy is needed.
        std::size_t old_size = pending.size();
        pending.resize(old_size + kReadSize);
        ssize_t n = ::recv(in_fd, pending.data() + old_size, kReadSize, 0);
        if (n < 0) {
            if (!verified && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                std::cerr << "ignoring connection: no data within "
                          << kFirstFrameTimeoutSec << "s\n";
                return SessionResult::Rejected;
            }
            std::perror("recv");
            return verified ? SessionResult::Failed : SessionResult::Rejected;
        }
        pending.resize(old_size + static_cast<std::size_t>(n));
        if (n == 0) break;                              // sender closed: EOF

        // Pull out every complete frame currently buffered.
        std::size_t offset = 0;
        for (;;) {
            FrameInfo f = next_frame(pending.data() + offset, pending.size() - offset);
            if (f.status == ParseStatus::NeedMore) break;
            if (f.status == ParseStatus::Invalid) {
                if (!verified) {
                    std::cerr << "ignoring connection: data is not FIRE STORM traffic\n";
                    return SessionResult::Rejected;
                }
                std::cerr << "unrecognised frame mid-stream; cannot resynchronise\n";
                return SessionResult::Failed;
            }

            if (!verified) {
                // First valid frame: this is the real sender. Drop the
                // timeout and open the forward connection.
                verified = true;
                set_recv_timeout(in_fd, 0);
                out = connect_to(kForwardPort);
                if (!out.valid()) return SessionResult::Failed;
                std::cout << "valid traffic, forwarding to " << kForwardPort << '\n';
            }

            const std::uint8_t* frame = pending.data() + offset;
            if (f.is_ctfs) {
                document.add(frame, f.length);
                ++ctfs_frames;
            } else {
                outbuf.insert(outbuf.end(), frame, frame + f.length);
                ++forwarded_frames;
            }
            offset += f.length;
        }

        // One send() per read instead of one per frame: fewer system calls.
        if (!outbuf.empty()) {
            if (!send_all(out.get(), outbuf.data(), outbuf.size())) return SessionResult::Failed;
            forwarded_bytes += outbuf.size();
            outbuf.clear();
        }
        // Drop the frames we've handled; any partial frame stays for the next read.
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    if (!verified) {
        std::cerr << "ignoring connection: closed without sending a valid frame\n";
        return SessionResult::Rejected;
    }
    if (!pending.empty())
        std::cerr << "warning: " << pending.size() << " trailing bytes did not form a whole frame\n";

    std::cout << "done: forwarded " << forwarded_frames << " frames (" << forwarded_bytes
              << " bytes), held back " << ctfs_frames << " CTFS frames\n";

    // Close the forward connection first so the receiver sees EOF straight away,
    // then save the document.
    out = Socket{};
    constexpr const char* kOutputPath = "output.pdf";
    if (!document.write(kOutputPath)) return SessionResult::Failed;
    std::cout << "wrote " << kOutputPath << " from " << document.chunk_count() << " chunks";
    if (document.duplicates() > 0) std::cout << " (" << document.duplicates() << " duplicates ignored)";
    std::cout << '\n';
    return SessionResult::Completed;
}

}  // namespace

int main() {
    Socket listener = listen_on(kListenPort);
    if (!listener.valid()) return EXIT_FAILURE;
    std::cout << "fire_storm: listening on " << kListenPort << '\n';

    // Keep accepting until one connection turns out to be the real stream.
    for (;;) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof peer;
        Socket in(::accept(listener.get(), reinterpret_cast<sockaddr*>(&peer), &peer_len));
        if (!in.valid()) {
            if (errno == EINTR) continue;
            std::perror("accept");
            return EXIT_FAILURE;
        }

        char ip[INET_ADDRSTRLEN] = "?";
        ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        std::cout << "connection from " << ip << ':' << ntohs(peer.sin_port) << '\n';

        switch (run_session(in.get())) {
            case SessionResult::Completed: return EXIT_SUCCESS;
            case SessionResult::Failed:    return EXIT_FAILURE;
            case SessionResult::Rejected:
                std::cout << "still listening on " << kListenPort << '\n';
                break;
        }
    }
}