import { AttackType } from "../api/generated";

export type AttackResolver = {
    [Key in AttackType]: {
        abbreviation: string;
        long: string;
        key: string;
    };
};

export const ATTACKS: AttackResolver = {
    BruteforceSubdomains: { abbreviation: "BSd", long: "Bruteforce Subdomains", key: "bruteforceSubdomains" },
    TcpPortScan: { abbreviation: "PsT", long: "TCP port scan", key: "tcpPortScan" },
    QueryCertificateTransparency: {
        abbreviation: "CT",
        long: "Certificate Transparency",
        key: "queryCertificateTransparency",
    },
    QueryUnhashed: { abbreviation: "Dh", long: "Dehashed", key: "queryDehashed" },
    HostAlive: { abbreviation: "HA", long: "Host alive", key: "hostAlive" },
    ServiceDetection: { abbreviation: "SvD", long: "Service Detection", key: "serviceDetection" },
    DnsResolution: { abbreviation: "DR", long: "DNS Resolution", key: "dnsResolution" },
    ForcedBrowsing: { abbreviation: "FB", long: "Forced Browsing", key: "forcedBrowsing" },
    OSDetection: { abbreviation: "OS", long: "OS Detection", key: "osDetection" },
    AntiPortScanningDetection: {
        abbreviation: "APs",
        long: "Anti port-scanning detection",
        key: "antiPortScanningDetection",
    },
    UdpPortScan: { abbreviation: "PsU", long: "UDP port scan", key: "udpPortScan" },
    VersionDetection: { abbreviation: "VsD", long: "Version detection", key: "versionDetection" },
    PortGuesser: { abbreviation: "PG", long: "Port guesser", key: "portGuesser" },
    Undefined: { abbreviation: "?", long: "Undefined", key: "undefined" },
};
