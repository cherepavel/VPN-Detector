#include <jni.h>

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <fstream>
#include <algorithm>

#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct AddressEntry {
    int family = 0;
    std::string address;
    std::string netmask;
    std::string peerOrBroadcast;
    bool isPointToPoint = false;
    bool isBroadcast = false;
};

struct InterfaceDump {
    std::string name;
    unsigned int flags = 0;
    std::vector<AddressEntry> addresses;
};

static std::string sockaddrToString(const sockaddr* sa) {
    if (!sa) return {};

    char buf[INET6_ADDRSTRLEN] = {};

    if (sa->sa_family == AF_INET) {
        if (const auto sin = reinterpret_cast<const sockaddr_in*>(sa); inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
            return buf;
        }
    } else if (sa->sa_family == AF_INET6) {
        if (const auto sin6 = reinterpret_cast<const sockaddr_in6*>(sa); inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) {
            return buf;
        }
    }

    return {};
}

static int readIntFromFile(const std::string& path, const int fallback = -1) {
    std::ifstream file(path);
    if (!file.is_open()) return fallback;

    int value = fallback;
    file >> value;
    return file.fail() ? fallback : value;
}

static std::string formatFlagNames(const unsigned int flags) {
    std::string result;

    const auto append = [&](const char* name) {
        if (!result.empty()) result += ',';
        result += name;
    };

    if (flags & IFF_UP) append("UP");
    if (flags & IFF_BROADCAST) append("BROADCAST");
    if (flags & IFF_DEBUG) append("DEBUG");
    if (flags & IFF_LOOPBACK) append("LOOPBACK");
    if (flags & IFF_POINTOPOINT) append("POINTOPOINT");
    if (flags & IFF_RUNNING) append("RUNNING");
    if (flags & IFF_NOARP) append("NOARP");
    if (flags & IFF_PROMISC) append("PROMISC");
    if (flags & IFF_ALLMULTI) append("ALLMULTI");
    if (flags & IFF_MULTICAST) append("MULTICAST");

    return result;
}

static int ipv6PrefixLenFromMask(const sockaddr* sa) {
    if (!sa || sa->sa_family != AF_INET6) return -1;

    const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
    int bits = 0;

    for (int i = 0; i < 16; ++i) {
        const unsigned char byte = sin6->sin6_addr.s6_addr[i];
        if (byte == 0xFF) {
            bits += 8;
        } else {
            for (int bit = 7; bit >= 0; --bit) {
                if (byte & (1u << bit)) {
                    bits++;
                } else {
                    return bits;
                }
            }
            return bits;
        }
    }

    return bits;
}

static bool addressEntryLess(const AddressEntry& a, const AddressEntry& b) {
    if (a.family != b.family) {
        return a.family == AF_INET;
    }
    return a.address < b.address;
}

// type values from linux/if_arp.h
static const char* ifTypeName(const int type) {
    switch (type) {
        case 1:     return "ETHER";
        case 772:   return "LOOPBACK";
        case 65534: return "TUN";
        default:    return nullptr;
    }
}

static std::string buildIfconfigLikeBlock(
        const InterfaceDump& iface,
        const std::map<std::string, int>& mtuMap,
        const std::map<std::string, int>& txQueueMap,
        const std::map<std::string, int>& typeMap) {
    std::ostringstream oss;

    const auto mtuIt  = mtuMap.find(iface.name);
    const auto txIt   = txQueueMap.find(iface.name);
    const auto typeIt = typeMap.find(iface.name);

    const int mtu    = mtuIt  != mtuMap.end()    ? mtuIt->second  : -1;
    const int txq    = txIt   != txQueueMap.end() ? txIt->second   : -1;
    const int ifType = typeIt != typeMap.end()    ? typeIt->second : -1;

    oss << iface.name << ": flags=" << iface.flags
        << "<" << formatFlagNames(iface.flags) << ">";

    if (mtu >= 0) {
        oss << "  mtu " << mtu;
    }
    if (ifType >= 0) {
        oss << "  type " << ifType;
        if (const char* typeName = ifTypeName(ifType)) {
            oss << " (" << typeName << ")";
        }
    }

    oss << "\n";

    std::vector<AddressEntry> sorted = iface.addresses;
    std::sort(sorted.begin(), sorted.end(), addressEntryLess);

    for (const auto&[family, address, netmask, peerOrBroadcast, isPointToPoint, isBroadcast] : sorted) {
        if (family == AF_INET) {
            oss << "        inet " << (address.empty() ? "-" : address);

            if (!netmask.empty()) {
                oss << "  netmask " << netmask;
            }

            if (!peerOrBroadcast.empty()) {
                if (isPointToPoint) {
                    oss << "  destination " << peerOrBroadcast;
                } else if (isBroadcast) {
                    oss << "  broadcast " << peerOrBroadcast;
                }
            }

            oss << "\n";
        } else if (family == AF_INET6) {
            oss << "        inet6 " << (address.empty() ? "-" : address);

            if (!netmask.empty()) {
                oss << "  prefixlen " << netmask;
            }

            if (!peerOrBroadcast.empty() && isPointToPoint) {
                oss << "  destination " << peerOrBroadcast;
            }

            oss << "\n";
        }
    }

    if (txq >= 0) {
        oss << "        txqueuelen " << txq << "\n";
    }

    return oss.str();
}

// --- /proc/net/route helpers ---

// /proc/net/route stores IPs as little-endian hex uint32
static std::string hexLeToIpStr(const std::string& hex) {
    const auto val = static_cast<unsigned long>(strtoul(hex.c_str(), nullptr, 16));
    return std::to_string(val & 0xFFu) + "." +
           std::to_string((val >> 8u) & 0xFFu) + "." +
           std::to_string((val >> 16u) & 0xFFu) + "." +
           std::to_string((val >> 24u) & 0xFFu);
}

static int countSetBits(unsigned long val) {
    int count = 0;
    while (val) {
        count += static_cast<int>(val & 1u);
        val >>= 1u;
    }
    return count;
}

// ---

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_cherepavel_vpndetector_detector_IfconfigTermuxLikeDetector_getInterfacesNative(
        JNIEnv* env,
        jobject /* thiz */) {

    jclass stringCls = env->FindClass("java/lang/String");
    if (stringCls == nullptr) {
        return nullptr;
    }

    std::map<std::string, InterfaceDump> interfaces;
    std::map<std::string, int> mtuMap;
    std::map<std::string, int> txQueueMap;
    std::map<std::string, int> typeMap;

    ::ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1 || ifaddr == nullptr) {
        return env->NewObjectArray(0, stringCls, nullptr);
    }

    for (const ::ifaddrs* it = ifaddr; it != nullptr; it = it->ifa_next) {
        if (!it->ifa_name) continue;

        std::string name(it->ifa_name);
        auto& iface = interfaces[name];

        iface.name = name;
        iface.flags |= it->ifa_flags;

        if (mtuMap.find(name) == mtuMap.end()) {
            mtuMap[name] = readIntFromFile("/sys/class/net/" + name + "/mtu", -1);
        }
        if (txQueueMap.find(name) == txQueueMap.end()) {
            txQueueMap[name] = readIntFromFile("/sys/class/net/" + name + "/tx_queue_len", -1);
        }
        if (typeMap.find(name) == typeMap.end()) {
            typeMap[name] = readIntFromFile("/sys/class/net/" + name + "/type", -1);
        }

        if (!it->ifa_addr) continue;

        const int family = it->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;

        AddressEntry entry;
        entry.family = family;
        entry.address = sockaddrToString(it->ifa_addr);
        entry.isPointToPoint = (it->ifa_flags & IFF_POINTOPOINT) != 0;
        entry.isBroadcast    = (it->ifa_flags & IFF_BROADCAST)   != 0;

        if (family == AF_INET) {
            entry.netmask = sockaddrToString(it->ifa_netmask);
        } else if (family == AF_INET6) {
            if (const int prefixLen = ipv6PrefixLenFromMask(it->ifa_netmask); prefixLen >= 0) {
                entry.netmask = std::to_string(prefixLen);
            }
        }

        if (entry.isPointToPoint && it->ifa_dstaddr) {
            entry.peerOrBroadcast = sockaddrToString(it->ifa_dstaddr);
        } else if (entry.isBroadcast && it->ifa_ifu.ifu_broadaddr) {
            entry.peerOrBroadcast = sockaddrToString(it->ifa_ifu.ifu_broadaddr);
        }

        iface.addresses.push_back(entry);
    }

    freeifaddrs(ifaddr);

    std::vector<std::string> dumps;
    dumps.reserve(interfaces.size());

    for (const auto& [_, iface] : interfaces) {
        dumps.push_back(buildIfconfigLikeBlock(iface, mtuMap, txQueueMap, typeMap));
    }

    jobjectArray result = env->NewObjectArray(
            static_cast<jsize>(dumps.size()),
            stringCls,
            nullptr
    );
    if (!result) {
        return nullptr;
    }

    for (jsize i = 0; i < static_cast<jsize>(dumps.size()); ++i) {
        jstring text = env->NewStringUTF(dumps[i].c_str());
        env->SetObjectArrayElement(result, i, text);
        env->DeleteLocalRef(text);
    }

    return result;
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_cherepavel_vpndetector_detector_IfconfigTermuxLikeDetector_getKernelRoutesNative(
        JNIEnv* env,
        jobject /* thiz */) {

    jclass stringCls = env->FindClass("java/lang/String");
    if (!stringCls) return nullptr;

    std::ifstream routeFile("/proc/net/route");
    if (!routeFile.is_open()) {
        return env->NewObjectArray(0, stringCls, nullptr);
    }

    std::vector<std::string> routes;
    std::string line;
    std::getline(routeFile, line); // skip header

    while (std::getline(routeFile, line)) {
        std::istringstream ss(line);
        std::string iface, dest, gw, flagsStr, refCnt, use, metric, mask;
        if (!(ss >> iface >> dest >> gw >> flagsStr >> refCnt >> use >> metric >> mask)) {
            continue;
        }

        const auto flags   = static_cast<unsigned long>(strtoul(flagsStr.c_str(), nullptr, 16));
        if (!(flags & 0x0001u)) continue; // skip non-UP routes

        const auto maskVal = static_cast<unsigned long>(strtoul(mask.c_str(), nullptr, 16));
        const auto destVal = static_cast<unsigned long>(strtoul(dest.c_str(), nullptr, 16));

        std::ostringstream route;
        route << iface << ": " << hexLeToIpStr(dest) << "/" << countSetBits(maskVal);

        if (flags & 0x0002u) { // RTF_GATEWAY
            route << " via " << hexLeToIpStr(gw);
        }

        if (destVal == 0 && maskVal == 0) {
            route << " [DEFAULT]";
        }

        routes.push_back(route.str());
    }

    jobjectArray result = env->NewObjectArray(
        static_cast<jsize>(routes.size()), stringCls, nullptr);
    if (!result) return nullptr;

    for (jsize i = 0; i < static_cast<jsize>(routes.size()); ++i) {
        jstring text = env->NewStringUTF(routes[i].c_str());
        env->SetObjectArrayElement(result, i, text);
        env->DeleteLocalRef(text);
    }

    return result;
}
