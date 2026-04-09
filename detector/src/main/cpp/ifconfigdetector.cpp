#include <jni.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace {

struct AddressEntry {
    int family = 0;
    std::string address;
    std::string netmask;
    std::string peerOrBroadcast;
    bool isPointToPoint = false;
    bool isBroadcast = false;

    explicit AddressEntry(const int fam = 0, std::string addr = {}, std::string mask = {}, std::string peer = {},
                          const bool p2p = false, const bool bc = false)
        : family(fam), address(std::move(addr)), netmask(std::move(mask)), peerOrBroadcast(std::move(peer)),
          isPointToPoint(p2p), isBroadcast(bc) {}
};

struct InterfaceDump {
    std::string name;
    unsigned int flags = 0;
    std::vector<AddressEntry> addresses;
};

struct IfAddrsGuard {
    ::ifaddrs *ptr = nullptr;

    ~IfAddrsGuard() {
        if (ptr)
            ::freeifaddrs(ptr);
    }

    // Использование: getifaddrs(ifaddr())
    ::ifaddrs **operator()() noexcept { return &ptr; }

    [[nodiscard]] ::ifaddrs *get() const noexcept { return ptr; }
    explicit operator ::ifaddrs *() const noexcept { return ptr; }
};

std::string sockaddrToString(const sockaddr *sa) {
    if (!sa)
        return {};

    char buf[INET6_ADDRSTRLEN] = {};
    if (sa->sa_family == AF_INET) {
        const auto *sin = reinterpret_cast<const sockaddr_in *>(sa);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
            return buf;
    } else if (sa->sa_family == AF_INET6) {
        const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)))
            return buf;
    }
    return {};
}

int readIntFromFile(const std::string &path, const int fallback = -1) {
    std::ifstream file(path);
    if (!file.is_open())
        return fallback;

    int value = fallback;
    file >> value;
    return file.fail() ? fallback : value;
}

std::string formatFlagNames(const unsigned int flags) {
    std::string result;
    const auto append = [&](const char *name) {
        if (!result.empty())
            result += ',';
        result += name;
    };

    if (flags & IFF_UP)
        append("UP");
    if (flags & IFF_BROADCAST)
        append("BROADCAST");
    if (flags & IFF_DEBUG)
        append("DEBUG");
    if (flags & IFF_LOOPBACK)
        append("LOOPBACK");
    if (flags & IFF_POINTOPOINT)
        append("POINTOPOINT");
    if (flags & IFF_RUNNING)
        append("RUNNING");
    if (flags & IFF_NOARP)
        append("NOARP");
    if (flags & IFF_PROMISC)
        append("PROMISC");
    if (flags & IFF_ALLMULTI)
        append("ALLMULTI");
    if (flags & IFF_MULTICAST)
        append("MULTICAST");

    return result;
}

int ipv6PrefixLenFromMask(const sockaddr *sa) {
    if (!sa || sa->sa_family != AF_INET6)
        return -1;

    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
    int bits = 0;
    for (int i = 0; i < 16; ++i) {
        const unsigned char byte = sin6->sin6_addr.s6_addr[i];
        if (byte == 0xFF) {
            bits += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if (byte & 1u << bit)
                ++bits;
            else
                return bits;
        }
        return bits;
    }
    return bits;
}

bool addressEntryLess(const AddressEntry &a, const AddressEntry &b) {
    if (a.family != b.family)
        return a.family == AF_INET;
    return a.address < b.address;
}

const char *ifTypeName(const int type) {
    switch (type) {
    case 1:
        return "ETHER";
    case 772:
        return "LOOPBACK";
    case 65534:
        return "TUN";
    default:
        return nullptr;
    }
}

std::string buildIfconfigLikeBlock(const InterfaceDump &iface, const std::map<std::string, int> &mtuMap,
                                   const std::map<std::string, int> &txQueueMap,
                                   const std::map<std::string, int> &typeMap) {
    std::ostringstream oss;

    oss << iface.name << ": flags=" << iface.flags << "<" << formatFlagNames(iface.flags) << ">";

    if (auto it = mtuMap.find(iface.name); it != mtuMap.end())
        oss << " mtu " << it->second;

    if (auto it = typeMap.find(iface.name); it != typeMap.end()) {
        const int t = it->second;
        oss << " type " << t;
        if (const char *name = ifTypeName(t))
            oss << " (" << name << ")";
    }
    oss << "\n";

    auto sorted = iface.addresses;
    std::sort(sorted.begin(), sorted.end(), addressEntryLess);

    for (const auto &entry : sorted) {
        if (entry.family == AF_INET) {
            oss << " inet " << (entry.address.empty() ? "-" : entry.address);
            if (!entry.netmask.empty())
                oss << " netmask " << entry.netmask;
            if (!entry.peerOrBroadcast.empty()) {
                if (entry.isPointToPoint)
                    oss << " destination " << entry.peerOrBroadcast;
                else if (entry.isBroadcast)
                    oss << " broadcast " << entry.peerOrBroadcast;
            }
            oss << "\n";
        } else if (entry.family == AF_INET6) {
            oss << " inet6 " << (entry.address.empty() ? "-" : entry.address);
            if (!entry.netmask.empty())
                oss << " prefixlen " << entry.netmask;
            if (!entry.peerOrBroadcast.empty() && entry.isPointToPoint)
                oss << " destination " << entry.peerOrBroadcast;
            oss << "\n";
        }
    }

    if (auto it = txQueueMap.find(iface.name); it != txQueueMap.end())
        oss << " txqueuelen " << it->second << "\n";

    return oss.str();
}

jobjectArray createStringArray(JNIEnv *env, const std::vector<std::string> &strings) {
    jclass stringCls = env->FindClass("java/lang/String");
    if (!stringCls)
        return nullptr;

    const auto size = static_cast<jsize>(strings.size());
    jobjectArray result = env->NewObjectArray(size, stringCls, nullptr);
    if (!result)
        return nullptr;

    for (jsize i = 0; i < size; ++i) {
        if (jstring text = env->NewStringUTF(strings[i].c_str())) {
            env->SetObjectArrayElement(result, i, text);
            env->DeleteLocalRef(text);
        }
    }
    return result;
}

// --- /proc/net/route helpers ---
std::string hexLeToIpStr(const std::string &hex) {
    const auto val = strtoul(hex.c_str(), nullptr, 16);
    return std::to_string(val & 0xFFu) + "." + std::to_string((val >> 8u) & 0xFFu) + "." +
           std::to_string((val >> 16u) & 0xFFu) + "." + std::to_string((val >> 24u) & 0xFFu);
}

int countSetBits(unsigned long val) {
    int count = 0;
    while (val) {
        count += static_cast<int>(val & 1u);
        val >>= 1u;
    }
    return count;
}

std::string hexToIpv6Str(const std::string &hex) {
    if (hex.size() != 32)
        return {};

    std::array<unsigned char, 16> bytes{};
    for (size_t i = 0; i < 16; ++i) {
        const auto part = hex.substr(i * 2, 2);
        char *end = nullptr;
        const auto value = strtoul(part.c_str(), &end, 16);
        if (end == nullptr || *end != '\0' || value > 0xFFu)
            return {};
        bytes[i] = static_cast<unsigned char>(value);
    }

    char buf[INET6_ADDRSTRLEN] = {};
    return inet_ntop(AF_INET6, bytes.data(), buf, sizeof(buf)) ? std::string(buf) : std::string();
}

std::vector<std::string> collectInterfaceDumps() {
    std::map<std::string, InterfaceDump> interfaces;
    std::map<std::string, int> mtuMap, txQueueMap, typeMap;

    IfAddrsGuard ipaddr;
    if (getifaddrs(ipaddr()) == -1 || ipaddr.get() == nullptr) {
        return {};
    }

    for (const ::ifaddrs *it = ipaddr.get(); it != nullptr; it = it->ifa_next) {
        if (!it->ifa_name)
            continue;

        const std::string name(it->ifa_name);
        auto &iface = interfaces[name];
        iface.name = name;
        iface.flags |= it->ifa_flags;

        if (mtuMap.find(name) == mtuMap.end())
            mtuMap[name] = readIntFromFile("/sys/class/net/" + name + "/mtu");
        if (txQueueMap.find(name) == txQueueMap.end())
            txQueueMap[name] = readIntFromFile("/sys/class/net/" + name + "/tx_queue_len");
        if (typeMap.find(name) == typeMap.end())
            typeMap[name] = readIntFromFile("/sys/class/net/" + name + "/type");

        if (!it->ifa_addr)
            continue;

        const int family = it->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;

        const bool isP2P = (it->ifa_flags & IFF_POINTOPOINT) != 0;
        const bool isBC = (it->ifa_flags & IFF_BROADCAST) != 0;

        std::string netmaskStr, peerStr;
        if (family == AF_INET) {
            netmaskStr = sockaddrToString(it->ifa_netmask);
            if (isP2P && it->ifa_dstaddr)
                peerStr = sockaddrToString(it->ifa_dstaddr);
            else if (isBC && it->ifa_ifu.ifu_broadaddr)
                peerStr = sockaddrToString(it->ifa_ifu.ifu_broadaddr);
        } else if (family == AF_INET6) {
            if (const int prefixLen = ipv6PrefixLenFromMask(it->ifa_netmask); prefixLen >= 0)
                netmaskStr = std::to_string(prefixLen);
            if (isP2P && it->ifa_dstaddr)
                peerStr = sockaddrToString(it->ifa_dstaddr);
        }

        const std::string adderStr = sockaddrToString(it->ifa_addr);
        iface.addresses.emplace_back(family, adderStr, std::move(netmaskStr), std::move(peerStr), isP2P, isBC);
    }

    std::vector<std::string> dumps;
    dumps.reserve(interfaces.size());
    for (const auto &[_, iface] : interfaces) {
        dumps.emplace_back(buildIfconfigLikeBlock(iface, mtuMap, txQueueMap, typeMap));
    }
    return dumps;
}

std::vector<std::string> parseKernelRoutes() {
    std::ifstream routeFile("/proc/net/route");
    if (!routeFile.is_open())
        return {};

    std::vector<std::string> routes;
    std::string line;
    std::getline(routeFile, line);  // skip header

    while (std::getline(routeFile, line)) {
        std::istringstream ss(line);
        std::string i_face, dest, gw, flagsStr, refCnt, use, metric, mask;

        if (!(ss >> i_face >> dest >> gw >> flagsStr >> refCnt >> use >> metric >> mask))
            continue;

        const auto flags = strtoul(flagsStr.c_str(), nullptr, 16);
        if (!(flags & 0x0001u))
            continue;

        const auto maskVal = strtoul(mask.c_str(), nullptr, 16);
        const auto destVal = strtoul(dest.c_str(), nullptr, 16);

        std::ostringstream route;
        route << i_face << ": " << hexLeToIpStr(dest) << "/" << countSetBits(maskVal);
        if (flags & 0x0002u)
            route << " via " << hexLeToIpStr(gw);
        if (destVal == 0 && maskVal == 0)
            route << " [DEFAULT]";

        routes.emplace_back(route.str());
    }
    return routes;
}

std::vector<std::string> parseKernelIpv6Routes() {
    std::ifstream routeFile("/proc/net/ipv6_route");
    if (!routeFile.is_open())
        return {};

    std::vector<std::string> routes;
    std::string line;

    while (std::getline(routeFile, line)) {
        std::istringstream ss(line);
        std::string destHex, destPrefixHex, srcHex, srcPrefixHex, nextHopHex, metricHex, refCntHex, useHex, flagsHex,
            iface;

        if (!(ss >> destHex >> destPrefixHex >> srcHex >> srcPrefixHex >> nextHopHex >> metricHex >> refCntHex >>
              useHex >> flagsHex >> iface))
            continue;

        if (const auto flags = strtoul(flagsHex.c_str(), nullptr, 16); !(flags & 0x0001u))
            continue;

        const auto destPrefix = strtoul(destPrefixHex.c_str(), nullptr, 16);
        const auto dest = hexToIpv6Str(destHex);
        const auto nextHop = hexToIpv6Str(nextHopHex);

        if (dest.empty())
            continue;

        std::ostringstream route;
        route << iface << ": " << dest << "/" << destPrefix;
        if (!nextHop.empty() && nextHop != "::")
            route << " via " << nextHop;
        if (destPrefix == 0 && dest == "::")
            route << " [DEFAULT]";

        routes.emplace_back(route.str());
    }
    return routes;
}

}  // anonymous namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_cherepavel_vpndetector_detector_IfconfigTermuxLikeDetector_getInterfacesNative(JNIEnv *env, jobject /*thiz*/) {
    return createStringArray(env, collectInterfaceDumps());
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_cherepavel_vpndetector_detector_IfconfigTermuxLikeDetector_getKernelRoutesNative(JNIEnv *env,
                                                                                          jobject /*thiz*/) {
    return createStringArray(env, parseKernelRoutes());
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_cherepavel_vpndetector_detector_IfconfigTermuxLikeDetector_getKernelIpv6RoutesNative(JNIEnv *env,
                                                                                              jobject /*thiz*/) {
    return createStringArray(env, parseKernelIpv6Routes());
}