import NetworkExtension
import OpenVPNAdapter

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    var startHandler: ((Error?) -> Void)?
    var stopHandler: (() -> Void)?
    let vpnReachability = OpenVPNReachability()
    
    lazy var vpnAdapter: OpenVPNAdapter = {
        let adapter = OpenVPNAdapter()
        adapter.delegate = self
        return adapter
    }()
    
    override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        guard let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol else {
            let error = NSError(domain: "PacketTunnelProvider", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid protocolConfiguration type"])
            completionHandler(error)
            return
        }
        
        // Получаем данные конфигурации OpenVPN
        guard let providerConfiguration = protocolConfiguration.providerConfiguration else {
            let error = NSError(domain: "PacketTunnelProvider", code: -2, userInfo: [NSLocalizedDescriptionKey: "Missing providerConfiguration"])
            completionHandler(error)
            return
        }
        
        guard let fileContent = providerConfiguration["configuration"] as? Data else {
            let error = NSError(domain: "PacketTunnelProvider", code: -3, userInfo: [NSLocalizedDescriptionKey: "Missing OpenVPN configuration data"])
            completionHandler(error)
            return
        }
        
        // Настраиваем OpenVPN конфигурацию
        let vpnConfiguration = OpenVPNConfiguration()
        vpnConfiguration.fileContent = fileContent
        vpnConfiguration.tunPersist = true
        
        // Применяем OpenVPN конфигурацию
        let properties: OpenVPNConfigurationEvaluation
        do {
            properties = try vpnAdapter.apply(configuration: vpnConfiguration)
        } catch {
            completionHandler(error)
            return
        }
        
        // Если требуется логин/пароль, передаём их
        if !properties.autologin {
            guard let username = options?["username"] as? String, let password = options?["password"] as? String else {
                let error = NSError(domain: "PacketTunnelProvider", code: -4, userInfo: [NSLocalizedDescriptionKey: "Missing username or password"])
                completionHandler(error)
                return
            }
            
            let credentials = OpenVPNCredentials()
            credentials.username = username
            credentials.password = password
            
            do {
                try vpnAdapter.provide(credentials: credentials)
            } catch {
                completionHandler(error)
                return
            }
        }
        
        // Настраиваем проверку доступности VPN сервера
        vpnReachability.startTracking { [weak self] status in
            guard status == .reachableViaWiFi else { return }
            self?.vpnAdapter.reconnect(afterTimeInterval: 5)
        }
        
        // Запускаем VPN подключение
        startHandler = completionHandler
        vpnAdapter.connect(using: self)
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopHandler = completionHandler
        vpnAdapter.disconnect()
    }
}

extension PacketTunnelProvider: OpenVPNAdapterDelegate {
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if String(data: messageData, encoding: .utf8) == "SOME_STATIC_KEY" {
            let bytesIn = Int64(self.vpnAdapter.transportStatistics.bytesIn)
            let bytesOut = Int64(self.vpnAdapter.transportStatistics.bytesOut)
            let dict: [String: Int64] = ["bytesIn": bytesIn, "bytesOut": bytesOut]
            
            do {
                let data = try NSKeyedArchiver.archivedData(withRootObject: dict, requiringSecureCoding: false)
                completionHandler?(data)
            } catch {
                print("Failed to encode traffic stats: \(error)")
                completionHandler?(nil)
            }
        }
    }

    
    func openVPNAdapter(_ openVPNAdapter: OpenVPNAdapter, configureTunnelWithNetworkSettings networkSettings: NEPacketTunnelNetworkSettings?, completionHandler: @escaping (Error?) -> Void) {
        networkSettings?.dnsSettings?.matchDomains = [""]
        setTunnelNetworkSettings(networkSettings, completionHandler: completionHandler)
    }
    
    func openVPNAdapter(_ openVPNAdapter: OpenVPNAdapter, handleEvent event: OpenVPNAdapterEvent, message: String?) {
        if let message = message {
            NSLog("[OpenVPN Message] \(message)")
        }
        
        switch event {
        case .connected:
            startHandler?(nil)
            startHandler = nil
        case .disconnected:
            stopHandler?()
            stopHandler = nil
        case .reconnecting:
            NSLog("[OpenVPN Event] Reconnecting...")
        default:
            break
        }
    }
    
    func openVPNAdapter(_ openVPNAdapter: OpenVPNAdapter, handleError error: Error) {
        NSLog("[OpenVPN Error] \(error)")
        
        guard let isFatal = (error as NSError).userInfo[OpenVPNAdapterErrorFatalKey] as? Bool, isFatal else {
            return
        }
        
        if let startHandler = startHandler {
            startHandler(error)
            self.startHandler = nil
        } else {
            cancelTunnelWithError(error)
        }
    }
    
    func openVPNAdapter(_ openVPNAdapter: OpenVPNAdapter, handleLogMessage logMessage: String) {
        NSLog("[OpenVPN Log] \(logMessage)")
    }
}

extension PacketTunnelProvider: OpenVPNAdapterPacketFlow {
    
    func readPackets(completionHandler: @escaping ([Data], [NSNumber]) -> Void) {
        packetFlow.readPackets(completionHandler: completionHandler)
    }
    
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        return packetFlow.writePackets(packets, withProtocols: protocols)
    }
}
