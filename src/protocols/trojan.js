/* eslint-disable no-undef */
/* eslint-disable no-unused-vars */
import { connect } from 'cloudflare:sockets';
import { sha224 } from 'js-sha256';

export async function TROverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;

    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (udpStreamWrite) {
                        return udpStreamWrite(chunk);
                    }

                    if (remoteSocketWapper.value) {
                        const writer = remoteSocketWapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const {
                        hasError,
                        message,
                        portRemote = 443,
                        addressRemote = "",
                        rawClientData,
                    } = parseTRHeader(chunk);

                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                    if (hasError) {
                        throw new Error(message);
                        // return;
                    }

                    handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
                },
                close() {
                    log(`readableWebSocketStream is closed`);
                },
                abort(reason) {
                    log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("readableWebSocketStream pipeTo error", err);
        });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

function parseTRHeader(buffer) {
    if (buffer.byteLength < 56) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }

    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid header format (missing CR LF)",
        };
    }

    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224(globalThis.TRPassword)) {
        return {
            hasError: true,
            message: "invalid password",
        };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data",
        };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed",
        };
    }

    const atype = view.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: {
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        }
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`,
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`,
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4),
    };
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    log
) {
    async function connectAndWrite(address, port) {
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }

    // if the cf connect tcp socket have no incoming data, we retry to redirect ip
    async function retry() {
        console.log('[TROJAN-RETRY] ========== TROJAN RETRY FUNCTION CALLED ==========');
        let proxyIP, proxyIpPort;
        const EncodedPanelProxyIPs = globalThis.pathName.split('/')[2] || '';
        console.log('[TROJAN-RETRY] EncodedPanelProxyIPs =', EncodedPanelProxyIPs);
        
        const proxyIPs = atob(EncodedPanelProxyIPs) || globalThis.proxyIPs;
        console.log('[TROJAN-RETRY] Final proxyIPs =', proxyIPs);
        
        const finalProxyIPs = proxyIPs.split(',').map(ip => ip.trim());
        console.log('[TROJAN-RETRY] finalProxyIPs array =', finalProxyIPs);
        
        const selectedProxy = finalProxyIPs[Math.floor(Math.random() * finalProxyIPs.length)];
        console.log('[TROJAN-RETRY] selectedProxy =', selectedProxy);
        
        // Check if it is a VLESS or Trojan protocol proxy
        if (selectedProxy.startsWith("vless://") || selectedProxy.startsWith("trojan://")) {
            console.log('[TROJAN-RETRY] Attempting protocol proxy connection...');
            const tcpSocket = await connectViaProtocolProxy(selectedProxy, addressRemote, portRemote, rawClientData, log);
            if (tcpSocket) {
                console.log('[TROJAN-RETRY] Protocol proxy connection successful!');
                tcpSocket.closed
                    .catch((error) => {
                        console.log("[TROJAN-RETRY] Protocol proxy tcpSocket closed error", error);
                    })
                    .finally(() => {
                        safeCloseWebSocket(webSocket);
                    });
                TRRemoteSocketToWS(tcpSocket, webSocket, null, log);
                return;
            } else {
                console.log('[TROJAN-RETRY] Protocol proxy connection failed');
            }
        } else {
            console.log('[TROJAN-RETRY] Using traditional proxy method');
        }

        // Traditional IP/domain proxy logic
        proxyIP = selectedProxy;
        if (proxyIP.includes(']:')) {
            const match = proxyIP.match(/^(\[.*?\]):(\d+)$/);
            proxyIP = match[1];
            proxyIpPort = +match[2];
        }

        if (proxyIP.split(':').length === 2) {
            proxyIP = proxyIP.split(':')[0];
            proxyIpPort = +proxyIP.split(':')[1];
        }

        const tcpSocket = await connectAndWrite(proxyIP || addressRemote, proxyIpPort || portRemote);
        // no matter retry success or not, close websocket
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                safeCloseWebSocket(webSocket);
            });

        TRRemoteSocketToWS(tcpSocket, webSocket, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    TRRemoteSocketToWS(tcpSocket, webSocket, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            // The event means that the client closed the client -> server stream.
            // However, the server -> client stream is still open until you call close() on the server side.
            // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
            webSocketServer.addEventListener("close", () => {
                // client send close, need close server
                // if stream is cancel, skip controller.close
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                controller.error(err);
            });
            // for ws 0rtt
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },
        cancel(reason) {
            // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
            // 2. if readableStream is cancel, all controller.close/enqueue need skip,
            // 3. but from testing controller.error still work even if readableStream is cancel
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });

    return stream;
}

async function TRRemoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() { },
                /**
                 *
                 * @param {Uint8Array} chunk
                 * @param {*} controller
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket connection is not open");
                    }
                    webSocket.send(chunk);
                },
                close() {
                    log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error("remoteSocket.readable abort", reason);
                },
            })
        )
        .catch((error) => {
            console.error(`trojanRemoteSocketToWS error:`, error.stack || error);
            safeCloseWebSocket(webSocket);
        });

    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        // go use modified Base64 for URL rfc4648 which js atob not support
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

/**
 * Connect to target server via VLESS or Trojan protocol proxy
 * @param {string} proxyUrl - Proxy protocol URL (vless:// or trojan://)
 * @param {string} targetHost - Target host
 * @param {number} targetPort - Target port
 * @param {Uint8Array} initialData - Initial data
 * @param {function} log - Log function
 * @returns {Promise<Socket|null>} Returns connected Socket or null
 */
async function connectViaProtocolProxy(proxyUrl, targetHost, targetPort, initialData, log) {
    console.log('[TROJAN-PROTOCOL-PROXY] ========== PROTOCOL PROXY FUNCTION CALLED ==========');
    console.log('[TROJAN-PROTOCOL-PROXY] Input parameters:', {
        proxyUrl: proxyUrl,
        targetHost: targetHost,
        targetPort: targetPort,
        initialDataLength: initialData.length
    });
    
    try {
        console.log('[TROJAN-PROTOCOL-PROXY] Parsing proxy URL...');
        const url = new URL(proxyUrl);
        const protocol = url.protocol.slice(0, -1); // Remove trailing ':'
        const proxyHost = url.hostname;
        const proxyPort = parseInt(url.port) || (protocol === 'vless' ? 443 : 443);
        
        console.log('[TROJAN-PROTOCOL-PROXY] Parsed URL details:', {
            protocol: protocol,
            proxyHost: proxyHost,
            proxyPort: proxyPort,
            username: url.username ? `${url.username.substring(0, 8)}...` : 'none'
        });
        
        log(`Connecting via ${protocol} proxy: ${proxyHost}:${proxyPort} -> ${targetHost}:${targetPort}`);
        
        // Connect to proxy server
        const proxySocket = connect({
            hostname: proxyHost,
            port: proxyPort,
        });
        
        console.log('[TROJAN-PROTOCOL-PROXY] Socket created successfully');
        
        if (protocol === 'vless') {
            console.log('[TROJAN-PROTOCOL-PROXY] Using VLESS protocol handler...');
            return await connectViaVlessProxy(proxySocket, url, targetHost, targetPort, initialData, log);
        } else if (protocol === 'trojan') {
            console.log('[TROJAN-PROTOCOL-PROXY] Using Trojan protocol handler...');
            return await connectViaTrojanProxy(proxySocket, url, targetHost, targetPort, initialData, log);
        }
        
        return null;
    } catch (error) {
        console.log('[TROJAN-PROTOCOL-PROXY] Error occurred:', error.message);
        log(`Protocol proxy connection failed: ${error.message}`);
        return null;
    }
}

/**
 * Connect via VLESS proxy
 * @param {Socket} proxySocket - Proxy Socket connection
 * @param {URL} proxyUrl - Proxy URL object
 * @param {string} targetHost - Target host
 * @param {number} targetPort - Target port
 * @param {Uint8Array} initialData - Initial data
 * @param {function} log - Log function
 * @returns {Promise<Socket>} Returns proxy Socket
 */
async function connectViaVlessProxy(proxySocket, proxyUrl, targetHost, targetPort, initialData, log) {
    console.log('[TROJAN-VLESS-PROXY] VLESS proxy handler called');
    const uuid = proxyUrl.username;
    
    // Build VLESS request header
    const vlessHeader = buildVlessHeader(uuid, targetHost, targetPort);
    
    // Send VLESS handshake and initial data
    const writer = proxySocket.writable.getWriter();
    await writer.write(new Uint8Array([...vlessHeader, ...initialData]));
    writer.releaseLock();
    
    log(`VLESS proxy handshake sent to ${targetHost}:${targetPort}`);
    return proxySocket;
}

/**
 * Connect via Trojan proxy
 * @param {Socket} proxySocket - Proxy Socket connection
 * @param {URL} proxyUrl - Proxy URL object
 * @param {string} targetHost - Target host
 * @param {number} targetPort - Target port
 * @param {Uint8Array} initialData - Initial data
 * @param {function} log - Log function
 * @returns {Promise<Socket>} Returns proxy Socket
 */
async function connectViaTrojanProxy(proxySocket, proxyUrl, targetHost, targetPort, initialData, log) {
    console.log('[TROJAN-TROJAN-PROXY] Trojan proxy handler called');
    const password = proxyUrl.username;
    
    // Build Trojan request header
    const trojanHeader = buildTrojanHeader(password, targetHost, targetPort);
    
    // Send Trojan handshake and initial data
    const writer = proxySocket.writable.getWriter();
    await writer.write(new Uint8Array([...trojanHeader, ...initialData]));
    writer.releaseLock();
    
    log(`Trojan proxy handshake sent to ${targetHost}:${targetPort}`);
    return proxySocket;
}

/**
 * Build VLESS protocol header
 * @param {string} uuid - User UUID
 * @param {string} targetHost - Target host
 * @param {number} targetPort - Target port
 * @returns {Uint8Array} VLESS protocol header byte array
 */
function buildVlessHeader(uuid, targetHost, targetPort) {
    const uuidBytes = parseUUID(uuid);
    const version = 0;
    const optLength = 0;
    const command = 1; // TCP
    
    // Address type and address
    let addressType, addressBytes;
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(targetHost)) {
        // IPv4
        addressType = 1;
        addressBytes = targetHost.split('.').map(num => parseInt(num));
    } else if (/^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(targetHost)) {
        // IPv6
        addressType = 3;
        const ipv6Parts = targetHost.split(':');
        addressBytes = [];
        ipv6Parts.forEach(part => {
            const num = parseInt(part, 16);
            addressBytes.push((num >> 8) & 0xff, num & 0xff);
        });
    } else {
        // Domain name
        addressType = 2;
        const hostBytes = new TextEncoder().encode(targetHost);
        addressBytes = [hostBytes.length, ...hostBytes];
    }
    
    // Port (big-endian)
    const portBytes = [(targetPort >> 8) & 0xff, targetPort & 0xff];
    
    return new Uint8Array([
        version,
        ...uuidBytes,
        optLength,
        command,
        ...portBytes,
        addressType,
        ...addressBytes
    ]);
}

/**
 * Build Trojan protocol header
 * @param {string} password - Trojan password
 * @param {string} targetHost - Target host
 * @param {number} targetPort - Target port
 * @returns {Uint8Array} Trojan protocol header byte array
 */
function buildTrojanHeader(password, targetHost, targetPort) {
    const passwordHash = sha224(password);
    const crlf = [0x0d, 0x0a];
    
    // SOCKS5 request format
    const cmd = 1; // CONNECT
    const rsv = 0; // Reserved field
    
    // Address type and address
    let atype, addressBytes;
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(targetHost)) {
        // IPv4
        atype = 1;
        addressBytes = targetHost.split('.').map(num => parseInt(num));
    } else if (/^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(targetHost)) {
        // IPv6
        atype = 4;
        const ipv6Parts = targetHost.split(':');
        addressBytes = [];
        ipv6Parts.forEach(part => {
            const num = parseInt(part, 16);
            addressBytes.push((num >> 8) & 0xff, num & 0xff);
        });
    } else {
        // Domain name
        atype = 3;
        const hostBytes = new TextEncoder().encode(targetHost);
        addressBytes = [hostBytes.length, ...hostBytes];
    }
    
    // Port (big-endian)
    const portBytes = [(targetPort >> 8) & 0xff, targetPort & 0xff];
    
    // Build complete Trojan header
    const passwordBytes = new TextEncoder().encode(passwordHash);
    const socks5Request = [cmd, rsv, atype, ...addressBytes, ...portBytes];
    
    return new Uint8Array([
        ...passwordBytes,
        ...crlf,
        ...socks5Request
    ]);
}

/**
 * Parse UUID string to byte array
 * @param {string} uuid - UUID string
 * @returns {Uint8Array} UUID byte array
 */
function parseUUID(uuid) {
    const hex = uuid.replace(/-/g, '');
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return bytes;
}