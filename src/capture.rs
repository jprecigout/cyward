//! Acquisition des paquets : capture en direct sur une interface, ou rejeu d'un fichier pcap.
//!
//! Chaque paquet est réduit à un [`PacketMeta`] (adresses, ports, drapeaux, taille, nom DNS)
//! avant d'être transmis au moteur de détection. Le contenu applicatif n'est jamais conservé.
//! Les trames ARP (IPv4 sur Ethernet) sont aussi transmises, avec l'adresse MAC de l'émetteur,
//! pour repérer l'usurpation ARP.
//!
//! La capture live utilise `pnet_datalink`, qui ouvre une socket `AF_PACKET` (Linux) sans
//! dépendre de libpcap. Elle requiert la capacité `CAP_NET_RAW`.

use std::{
    net::IpAddr,
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use etherparse::{ArpOperation, ArpPacketSlice, NetSlice, SlicedPacket, TransportSlice};
use pcap_file::{DataLink, pcap::PcapReader};
use pnet_datalink::{Channel, NetworkInterface};
use tokio::sync::mpsc;

use crate::stats::Stats;

/// Protocole de transport, réduit à ce qui intéresse les détecteurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    /// Trame ARP : ni IP ni transport, voir [`PacketMeta::arp`].
    Arp,
    Other,
}

/// Drapeaux TCP utiles à la détection (les autres ne sont pas conservés).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
}

impl TcpFlags {
    /// Premier paquet d'une poignée de main TCP.
    pub fn is_connection_start(&self) -> bool {
        self.syn && !self.ack
    }
}

/// Type de message ARP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    /// « Qui a cette IP ? » (diffusé à tout le réseau local).
    Request,
    /// « Cette IP est à moi » ; non sollicitée, c'est un ARP gratuit.
    Reply,
}

/// Contenu utile d'une trame ARP : l'association IP → MAC que l'émetteur annonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpInfo {
    pub op: ArpOp,
    /// Adresse MAC que l'émetteur associe à son IP (`PacketMeta::src`).
    pub sender_mac: [u8; 6],
}

/// Résumé d'un paquet IP ou d'une trame ARP : tout ce dont les détecteurs ont besoin, sans le contenu.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    /// Secondes depuis l'epoch (horloge de capture, ou celle du fichier pcap en rejeu).
    pub ts: f64,
    /// Adresses IP source et destination ; pour l'ARP, IP de l'émetteur et IP demandée.
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: Proto,
    /// Ports source et destination (0 hors TCP/UDP).
    pub sport: u16,
    pub dport: u16,
    /// Taille totale de la trame, en octets.
    pub len: u32,
    pub tcp: TcpFlags,
    /// Nom demandé si c'est une requête DNS.
    pub dns_query: Option<String>,
    /// Renseigné uniquement pour une trame ARP (`proto == Proto::Arp`).
    pub arp: Option<ArpInfo>,
}

/// Format de la couche liaison des trames reçues, qui détermine où commence l'en-tête IP.
#[derive(Clone, Copy)]
pub enum LinkType {
    /// Trames Ethernet classiques (cas normal).
    Ethernet,
    /// En-tête « Linux cooked » produit par `tcpdump -i any`.
    LinuxSll,
    /// Paquets IP sans en-tête de liaison (interfaces tun/VPN, certains pcap).
    RawIp,
}

/// Décode une trame et en extrait les métadonnées. Renvoie `None` pour ce qui n'est ni de
/// l'IP ni de l'ARP IPv4 sur Ethernet, ou pour une trame tronquée ou mal formée.
pub fn parse_packet(data: &[u8], link: LinkType, ts: f64) -> Option<PacketMeta> {
    // etherparse découpe la trame en couches sans copier les données.
    let sliced = match link {
        LinkType::Ethernet => SlicedPacket::from_ethernet(data),
        LinkType::LinuxSll => SlicedPacket::from_linux_sll(data),
        LinkType::RawIp => SlicedPacket::from_ip(data),
    }
    .ok()?;

    // Couche réseau : on ne garde que l'IPv4 et l'IPv6.
    let (src, dst) = match sliced.net? {
        NetSlice::Ipv4(ip) => (IpAddr::V4(ip.header().source_addr()), IpAddr::V4(ip.header().destination_addr())),
        NetSlice::Ipv6(ip) => (IpAddr::V6(ip.header().source_addr()), IpAddr::V6(ip.header().destination_addr())),
        NetSlice::Arp(arp) => return parse_arp(&arp, data.len() as u32, ts),
    };

    let mut meta = PacketMeta {
        ts,
        src,
        dst,
        proto: Proto::Other,
        sport: 0,
        dport: 0,
        len: data.len() as u32,
        tcp: TcpFlags::default(),
        dns_query: None,
        arp: None,
    };

    // Couche transport : complète les champs selon le protocole.
    match sliced.transport {
        Some(TransportSlice::Tcp(t)) => {
            meta.proto = Proto::Tcp;
            meta.sport = t.source_port();
            meta.dport = t.destination_port();
            meta.tcp = TcpFlags { syn: t.syn(), ack: t.ack() };
        }
        Some(TransportSlice::Udp(u)) => {
            meta.proto = Proto::Udp;
            meta.sport = u.source_port();
            meta.dport = u.destination_port();
            // Seules les requêtes vers le port 53 sont décodées (le DNS sur TCP ou chiffré, DoH/DoT, ne l'est pas).
            if meta.dport == 53 {
                meta.dns_query = parse_dns_query(u.payload());
            }
        }
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => meta.proto = Proto::Icmp,
        _ => {}
    }
    Some(meta)
}

/// Réduit une trame ARP à l'association annoncée (IP et MAC de l'émetteur). Seul l'ARP
/// Ethernet/IPv4 est gardé : l'IPv6 utilise NDP, et les autres variantes n'existent guère en pratique.
fn parse_arp(arp: &ArpPacketSlice, len: u32, ts: f64) -> Option<PacketMeta> {
    let arp = arp.to_packet().try_eth_ipv4().ok()?;
    let op = match arp.operation {
        ArpOperation::REQUEST => ArpOp::Request,
        ArpOperation::REPLY => ArpOp::Reply,
        _ => return None, // RARP, InARP… : sans intérêt ici
    };
    Some(PacketMeta {
        ts,
        src: IpAddr::V4(arp.sender_ipv4_addr()),
        dst: IpAddr::V4(arp.target_ipv4_addr()),
        proto: Proto::Arp,
        sport: 0,
        dport: 0,
        len,
        tcp: TcpFlags::default(),
        dns_query: None,
        arp: Some(ArpInfo { op, sender_mac: arp.sender_mac }),
    })
}

/// Extrait le nom de la première question d'une requête DNS (sans gérer la compression,
/// inutile dans une question).
pub fn parse_dns_query(payload: &[u8]) -> Option<String> {
    // En-tête DNS : 12 octets (identifiant, drapeaux, puis 4 compteurs de 16 bits).
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    // Le bit de poids fort des drapeaux (QR) vaut 1 pour une réponse.
    if flags & 0x8000 != 0 || qdcount == 0 {
        return None; // réponse, ou pas de question
    }
    // Le nom suit l'en-tête, encodé en segments « longueur + octets », terminé par un 0.
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        // `get` renvoie None si le paquet est tronqué : le `?` abandonne proprement.
        let len = *payload.get(pos)? as usize;
        if len == 0 {
            break;
        }
        // Un segment fait au plus 63 octets ; au-delà, c'est un pointeur de compression
        // ou un paquet malformé. La borne sur le nombre de segments protège d'un paquet piégé.
        if len > 63 || labels.len() > 127 {
            return None;
        }
        let label = payload.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

/// Horloge murale en secondes depuis l'epoch, au même format que les horodatages pcap.
fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub fn list_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
}

/// Choisit l'interface à écouter : celle demandée, sinon celle de la route par défaut,
/// sinon la première interface active non-loopback ayant une adresse.
pub fn pick_interface(name: &str) -> Result<NetworkInterface> {
    let ifaces = list_interfaces();
    if !name.is_empty() {
        return ifaces
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| anyhow!("interface {name} introuvable (voir `cyward interfaces`)"));
    }
    if let Some(default) = default_route_interface()
        && let Some(i) = ifaces.iter().find(|i| i.name == default)
    {
        return Ok(i.clone());
    }
    ifaces
        .into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .ok_or_else(|| anyhow!("aucune interface active trouvée, précisez capture.interface"))
}

/// Interface portant la route par défaut : c'est elle qui voit le trafic vers Internet,
/// plutôt qu'un pont Docker ou un tunnel VPN.
fn default_route_interface() -> Option<String> {
    // /proc/net/route : une ligne d'en-tête, puis une route par ligne. Colonnes utilisées :
    // 0 = interface, 1 = destination en hexadécimal (00000000 = route par défaut), 6 = métrique.
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    routes
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.len() > 6 && f[1] == "00000000")
        .min_by_key(|f| f[6].parse::<u32>().unwrap_or(u32::MAX)) // plus petite métrique
        .map(|f| f[0].to_string())
}

/// Capture en continu sur une interface. Tourne dans un thread dédié car la lecture est bloquante.
pub fn spawn_live(iface: NetworkInterface, promiscuous: bool, tx: mpsc::Sender<PacketMeta>, stats: Arc<Stats>) -> Result<()> {
    let config = pnet_datalink::Config { promiscuous, ..Default::default() };
    // pnet renvoie un émetteur et un récepteur de trames ; seul le récepteur sert ici.
    let (_, mut rx) = match pnet_datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => bail!("type de canal non supporté sur {}", iface.name),
        // Cas le plus fréquent au premier lancement : message explicite avec la commande à taper.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => bail!(
            "capture refusée sur {} : lancez en root ou donnez la capacité au binaire :\n  sudo setcap cap_net_raw,cap_net_admin=eip {}",
            iface.name,
            std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "cyward".into())
        ),
        Err(e) => return Err(e).context(format!("ouverture de {}", iface.name)),
    };
    // Une interface sans adresse MAC (tun, VPN) livre des paquets IP sans en-tête Ethernet.
    let link = if iface.is_loopback() || iface.mac.is_some() { LinkType::Ethernet } else { LinkType::RawIp };

    std::thread::Builder::new().name("capture".into()).spawn(move || {
        loop {
            match rx.next() {
                Ok(data) => {
                    stats.packets.fetch_add(1, Ordering::Relaxed);
                    stats.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    // `try_send` ne bloque pas : si le moteur est en retard, le paquet est
                    // compté comme perdu. Mieux vaut perdre un paquet que geler la capture.
                    if let Some(meta) = parse_packet(data, link, now_secs())
                        && tx.try_send(meta).is_err()
                    {
                        // Canal fermé = le moteur s'est arrêté : le thread se termine.
                        if tx.is_closed() {
                            break;
                        }
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    // Erreur transitoire (interface qui tombe…) : on patiente et on réessaie.
                    tracing::error!("erreur de capture : {e}");
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    })?;
    Ok(())
}

/// Délai à attendre avant de transmettre un paquet pour respecter le rythme du pcap accéléré
/// `speed` fois. `offset` : écart entre ce paquet et le premier, en secondes de temps du pcap ;
/// `elapsed` : temps réel écoulé depuis le premier, en secondes. None = le paquet part tout de suite.
pub fn pace_delay(offset: f64, elapsed: f64, speed: f64) -> Option<std::time::Duration> {
    let wait = offset / speed - elapsed;
    // En dessous d'une milliseconde, attendre coûterait plus que l'écart à corriger.
    (wait > 0.001).then(|| std::time::Duration::from_secs_f64(wait))
}

/// Rejoue un fichier pcap (format tcpdump classique) avec ses horodatages d'origine : à pleine
/// vitesse, ou au rythme de la capture accéléré `speed` fois (pour suivre la vue des flux).
pub async fn replay(path: &Path, tx: mpsc::Sender<PacketMeta>, stats: Arc<Stats>, speed: Option<f64>) -> Result<()> {
    let file = std::fs::File::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
    let mut reader = PcapReader::new(std::io::BufReader::new(file))
        .context("fichier pcap invalide (pcapng non supporté : convertir avec `editcap -F pcap`)")?;
    // Le type de lien est déclaré une fois dans l'en-tête global du fichier.
    let link = match reader.header().datalink {
        DataLink::ETHERNET => LinkType::Ethernet,
        DataLink::LINUX_SLL => LinkType::LinuxSll,
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => LinkType::RawIp,
        other => bail!("type de lien pcap non supporté : {other:?}"),
    };
    // Instant réel et horodatage du premier paquet, référence du rythme quand `speed` est donné.
    let mut origin: Option<(tokio::time::Instant, f64)> = None;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        if let Some(speed) = speed {
            let ts = pkt.timestamp.as_secs_f64();
            let (start, first) = *origin.get_or_insert((tokio::time::Instant::now(), ts));
            if let Some(d) = pace_delay(ts - first, start.elapsed().as_secs_f64(), speed) {
                tokio::time::sleep(d).await;
            }
        }
        stats.packets.fetch_add(1, Ordering::Relaxed);
        stats.bytes.fetch_add(pkt.orig_len as u64, Ordering::Relaxed);
        if let Some(mut meta) = parse_packet(&pkt.data, link, pkt.timestamp.as_secs_f64()) {
            // `orig_len` est la taille réelle du paquet sur le réseau, même si la capture
            // l'a tronqué (option -s de tcpdump).
            meta.len = pkt.orig_len;
            // `send(...).await` (et non try_send) : en rejeu, on attend le moteur plutôt que de perdre des paquets.
            tx.send(meta).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Construit le contenu UDP d'une requête DNS de type A pour `name`.
    fn dns_query(name: &str) -> Vec<u8> {
        // En-tête : identifiant 0x1234, drapeaux 0x0100 (requête récursive), 1 question.
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        // Fin du nom, type A (1), classe IN (1).
        p.extend_from_slice(&[0, 0, 1, 0, 1]);
        p
    }

    // Un paquet en avance sur le rythme attend ; un paquet en retard, ou à moins d'1 ms près, part tout de suite.
    #[test]
    fn replay_pacing() {
        // 10 s de pcap à ×20 = 0,5 s réelle ; 0,2 s déjà écoulées → 0,3 s d'attente.
        let d = pace_delay(10.0, 0.2, 20.0).unwrap();
        assert!((d.as_secs_f64() - 0.3).abs() < 1e-9);
        assert_eq!(pace_delay(10.0, 0.6, 20.0), None);
        assert_eq!(pace_delay(0.01, 0.0, 20.0), None);
    }

    #[test]
    fn parses_dns_question() {
        assert_eq!(parse_dns_query(&dns_query("www.Example.com")).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn ignores_dns_response() {
        let mut p = dns_query("example.com");
        // Active le bit QR : le paquet devient une réponse.
        p[2] |= 0x80;
        assert_eq!(parse_dns_query(&p), None);
    }

    #[test]
    fn parses_tcp_syn_over_ethernet() {
        let builder =
            etherparse::PacketBuilder::ethernet2([1; 6], [2; 6]).ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).tcp(40000, 22, 1, 1024).syn();
        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();
        let m = parse_packet(&buf, LinkType::Ethernet, 1.0).unwrap();
        assert_eq!(m.proto, Proto::Tcp);
        assert_eq!(m.dport, 22);
        assert!(m.tcp.is_connection_start());
    }

    // Une réponse ARP est décodée : IP et MAC de l'émetteur, IP visée.
    #[test]
    fn parses_arp_reply() {
        let arp = etherparse::ArpEthIpv4Packet {
            operation: ArpOperation::REPLY,
            sender_mac: [2, 0, 0, 0, 0, 9],
            sender_ipv4: [192, 168, 1, 1],
            target_mac: [2, 0, 0, 0, 0, 2],
            target_ipv4: [192, 168, 1, 20],
        };
        let mut buf = Vec::new();
        etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 9], [2, 0, 0, 0, 0, 2]).arp(arp.to_arp_packet()).write(&mut buf).unwrap();
        let m = parse_packet(&buf, LinkType::Ethernet, 1.0).unwrap();
        assert_eq!(m.proto, Proto::Arp);
        assert_eq!(m.src, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(m.dst, "192.168.1.20".parse::<IpAddr>().unwrap());
        assert_eq!(m.arp, Some(ArpInfo { op: ArpOp::Reply, sender_mac: [2, 0, 0, 0, 0, 9] }));
    }

    // Un paquet IP n'a pas d'information ARP.
    #[test]
    fn ip_packet_has_no_arp_info() {
        let mut buf = Vec::new();
        etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(1000, 2000)
            .write(&mut buf, &[])
            .unwrap();
        assert!(parse_packet(&buf, LinkType::Ethernet, 1.0).unwrap().arp.is_none());
    }
}
