/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
import { connect } from 'cloudflare:sockets';
import { isValidUUID } from '../helpers/helpers';
import { sha224 } from 'js-sha256';

/**
 * Handles VL over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VL header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
export async function VLOverWSHandler(request) {
    /** @type {import("@cloudflare/workers-types").WebSocket[]} */
    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    // ws --> remote
    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (isDns && udpStreamWrite) {
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
                        rawDataIndex,
                        VLVersion = new Uint8Array([0, 0]),
                        isUDP,
                    } = processVLHeader(chunk, globalThis.userID);
                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
                    if (hasError) {
                        // controller.error(message);
                        throw new Error(message); // cf seems has bug, controller.error will not end stream
                        // webSocket.close(1000, message);
                        // return;
                    }
                    // if UDP but port not DNS port, close it
                    if (isUDP) {
                        if (portRemote === 53) {
                            isDns = true;
                        } else {
                            // controller.error('UDP proxy only enable for DNS which is port 53');
                            throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
                            // return;
                        }
                    }
                    // ["version", "附加信息长度 N"]
                    const VLResponseHeader = new Uint8Array([VLVersion[0], 0]);
                    const rawClientData = chunk.slice(rawDataIndex);

                    // TODO: support udp here when cf runtime has udp support
                    if (isDns) {
                        const { write } = await handleUDPOutBound(webSocket, VLResponseHeader, log);
                        udpStreamWrite = write;
                        udpStreamWrite(rawClientData);
                        return;
                    }

                    handleTCPOutBound(
                        remoteSocketWapper,
                        addressRemote,
                        portRemote,
                        rawClientData,
                        webSocket,
                        VLResponseHeader,
                        log
                    );
                },
                close() {
                    log(`readableWebSocketStream is close`);
                },
                abort(reason) {
                    log(`readableWebSocketStream is abort`, JSON.stringify(reason));
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

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} VLResponseHeader The VL response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    VLResponseHeader,
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
        console.log('[VLESS-RETRY] ========== VLESS RETRY FUNCTION CALLED ==========');
        let proxyIP, proxyIpPort;
        const EncodedPanelProxyIPs = globalThis.pathName.split('/')[2] || '';
        console.log('[VLESS-RETRY] EncodedPanelProxyIPs =', EncodedPanelProxyIPs);
        
        const proxyIPs = atob(EncodedPanelProxyIPs) || globalThis.proxyIPs;
        console.log('[VLESS-RETRY] Final proxyIPs =', proxyIPs);
        
        const finalProxyIPs = proxyIPs.split(',').map(ip => ip.trim());
        console.log('[VLESS-RETRY] finalProxyIPs array =', finalProxyIPs);
        
        const selectedProxy = finalProxyIPs[Math.floor(Math.random() * finalProxyIPs.length)];
        console.log('[VLESS-RETRY] selectedProxy =', selectedProxy);
        
        // Check if it is a VLESS or Trojan protocol proxy
        if (selectedProxy.startsWith("vless://") || selectedProxy.startsWith("trojan://")) {
            console.log('[VLESS-RETRY] Attempting protocol proxy connection...');
            const tcpSocket = await connectViaProtocolProxy(selectedProxy, addressRemote, portRemote, rawClientData, log);
            if (tcpSocket) {
                console.log('[VLESS-RETRY] Protocol proxy connection successful!');
                tcpSocket.closed
                    .catch((error) => {
                        console.log("[VLESS-RETRY] Protocol proxy tcpSocket closed error", error);
                    })
                    .finally(() => {
                        safeCloseWebSocket(webSocket);
                    });
                VLRemoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
                return;
            } else {
                console.log('[VLESS-RETRY] Protocol proxy connection failed');
            }
        } else {
            console.log('[VLESS-RETRY] Using traditional proxy method');
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

        VLRemoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    VLRemoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, retry, log);
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

/**
 * Processes the VL header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} VLBuffer The VL header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VL header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  VLVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VL header buffer.
 */
function processVLHeader(VLBuffer, userID) {
    if (VLBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }
    const version = new Uint8Array(VLBuffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;
    const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    isValidUser = slicedBufferString === userID;

    if (!isValidUser) {
        return {
            hasError: true,
            message: "invalid user",
        };
    }

    const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];
    //skip opt for now

    const command = new Uint8Array(VLBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) { /* empty */ } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(VLBuffer.slice(addressIndex, addressIndex + 1));

    // 1--> ipv4  addressLength =4
    // 2--> domain name addressLength=addressBuffer[1]
    // 3--> ipv6  addressLength =16
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: {
            addressLength = 16;
            const dataView = new DataView(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            // seems no need add [] for ipv6
            break;
        }
        default:
            return {
                hasError: true,
                message: `invild  addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        VLVersion: version,
        isUDP,
    };
}

/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} VLResponseHeader The VL response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function VLRemoteSocketToWS(remoteSocket, webSocket, VLResponseHeader, retry, log) {
    // 检查代理URL是否是WebSocket类型
    const pathParts = globalThis.pathName.split('/');
    const encodedProxyURL = pathParts.length > 2 ? pathParts[2] : '';
    let isWebSocketProxy = false;
    
    if (encodedProxyURL) {
        try {
            const decodedURL = atob(encodedProxyURL);
            isWebSocketProxy = decodedURL.includes('type=ws');
            if (isWebSocketProxy) {
                console.log('[VLESS-RELAY] Detected WebSocket proxy');
            }
        } catch (e) {
            // Ignore decode errors
        }
    }
    
    // remote--> ws
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let VLHeader = VLResponseHeader;
    let hasIncomingData = false; // check if remoteSocket has incoming data
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
                    // remoteChunkCount++;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket.readyState is not open, maybe close");
                    }
                    
                    // 如果是WebSocket代理，需要解析WebSocket帧
                    let processedChunk = chunk;
                    if (isWebSocketProxy) {
                        try {
                            const parsedData = parseWebSocketFrame(chunk);
                            if (parsedData) {
                                processedChunk = parsedData;
                            }
                        } catch (error) {
                            console.log('[VLESS-RELAY] WebSocket frame parsing error:', error.message);
                        }
                    }
                    
                    if (VLHeader) {
                        webSocket.send(await new Blob([VLHeader, processedChunk]).arrayBuffer());
                        VLHeader = null;
                    } else {
                        webSocket.send(processedChunk);
                    }
                },
                close() {
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(`VLRemoteSocketToWS has exception `, error.stack || error);
            safeCloseWebSocket(webSocket);
        });

    // seems is cf connect socket have error,
    // 1. Socket.closed will have error
    // 2. Socket.readable will be close without any data coming
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

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        "-" +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        "-" +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        "-" +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        "-" +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw TypeError("Stringified UUID is invalid");
    }
    return uuid;
}

/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} VLResponseHeader The VL response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, VLResponseHeader, log) {
    let isVLHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) { },
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) { },
    });

    // only handle dns udp for now
    transformStream.readable
        .pipeTo(
            new WritableStream({
                async write(chunk) {
                    const resp = await fetch(
                        globalThis.dohURL, // dns server url
                        {
                            method: "POST",
                            headers: {
                                "content-type": "application/dns-message",
                            },
                            body: chunk,
                        }
                    );
                    const dnsQueryResult = await resp.arrayBuffer();
                    const udpSize = dnsQueryResult.byteLength;
                    // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
                    const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        log(`doh success and dns message length is ${udpSize}`);
                        if (isVLHeaderSent) {
                            webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                        } else {
                            webSocket.send(await new Blob([VLResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                            isVLHeaderSent = true;
                        }
                    }
                },
            })
        )
        .catch((error) => {
            log("dns udp has error" + error);
        });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         *
         * @param {Uint8Array} chunk
        */
        write(chunk) {
            writer.write(chunk);
        },
    };
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
    console.log('[VLESS-PROTOCOL-PROXY] ========== PROTOCOL PROXY FUNCTION CALLED ==========');
    console.log('[VLESS-PROTOCOL-PROXY] Input parameters:', {
        proxyUrl: proxyUrl,
        targetHost: targetHost,
        targetPort: targetPort,
        initialDataLength: initialData.length
    });
    
    try {
        console.log('[VLESS-PROTOCOL-PROXY] Parsing proxy URL...');
        const url = new URL(proxyUrl);
        const protocol = url.protocol.slice(0, -1); // Remove trailing ':'
        const proxyHost = url.hostname;
        const proxyPort = parseInt(url.port) || (protocol === 'vless' ? 443 : 443);
        
        console.log('[VLESS-PROTOCOL-PROXY] Parsed URL details:', {
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
        
        console.log('[VLESS-PROTOCOL-PROXY] Socket created successfully');
        
        if (protocol === 'vless') {
            console.log('[VLESS-PROTOCOL-PROXY] Using VLESS protocol handler...');
            return await connectViaVlessProxy(proxySocket, url, targetHost, targetPort, initialData, log);
        } else if (protocol === 'trojan') {
            console.log('[VLESS-PROTOCOL-PROXY] Using Trojan protocol handler...');
            return await connectViaTrojanProxy(proxySocket, url, targetHost, targetPort, initialData, log);
        }
        
        return null;
    } catch (error) {
        console.log('[VLESS-PROTOCOL-PROXY] Error occurred:', error.message);
        log(`Protocol proxy connection failed: ${error.message}`);
        return null;
    }
}

/**
 * 通过VLESS代理连接
 * @param {Socket} proxySocket - 代理Socket连接
 * @param {URL} proxyUrl - 代理URL对象
 * @param {string} targetHost - 目标主机
 * @param {number} targetPort - 目标端口
 * @param {Uint8Array} initialData - 初始数据
 * @param {function} log - 日志函数
 * @returns {Promise<Socket>} 返回代理Socket
 */
async function connectViaVlessProxy(proxySocket, proxyUrl, targetHost, targetPort, initialData, log) {
    console.log('[VLESS-PROXY] VLESS proxy handler called');
    const uuid = proxyUrl.username;
    const params = new URLSearchParams(proxyUrl.search);
    const wsType = params.get('type');
    const wsPath = params.get('path') || '/';
    const wsHost = params.get('host') || proxyUrl.hostname;
    
    try {
        // 如果是WebSocket类型，需要先进行WebSocket握手
        if (wsType === 'ws') {
            console.log('[VLESS-PROXY] Performing WebSocket handshake...');
            
            // 构建WebSocket握手请求
            const wsKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
            const wsRequest = [
                `GET ${wsPath} HTTP/1.1`,
                `Host: ${wsHost}`,
                `Upgrade: websocket`,
                `Connection: Upgrade`,
                `Sec-WebSocket-Key: ${wsKey}`,
                `Sec-WebSocket-Version: 13`,
                `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`,
                '',
                ''
            ].join('\r\n');
            
            const writer = proxySocket.writable.getWriter();
            await writer.write(new TextEncoder().encode(wsRequest));
            writer.releaseLock();
            
            // 等待WebSocket握手响应
            const reader = proxySocket.readable.getReader();
            const { value: responseData, done } = await reader.read();
            reader.releaseLock();
            
            if (done || !responseData) {
                console.log('[VLESS-PROXY] WebSocket handshake failed: no response');
                return null;
            }
            
            const response = new TextDecoder().decode(responseData);
            console.log('[VLESS-PROXY] WebSocket handshake response:', response.split('\r\n')[0]);
            
            if (!response.includes('101 Switching Protocols')) {
                console.log('[VLESS-PROXY] WebSocket handshake failed');
                return null;
            }
            
            console.log('[VLESS-PROXY] WebSocket handshake successful');
        }
        
        // 构建VLESS请求头
        const vlessHeader = buildVlessHeader(uuid, targetHost, targetPort);
        
        // 发送VLESS握手和初始数据
        const writer = proxySocket.writable.getWriter();
        
        // 安全的数据合并，不使用展开运算符
        const headerArray = vlessHeader instanceof Uint8Array ? vlessHeader : new Uint8Array(vlessHeader);
        const dataArray = initialData instanceof Uint8Array ? initialData : new Uint8Array(initialData);
        
        let finalData;
        if (wsType === 'ws') {
            // 对于WebSocket，需要将数据包装成WebSocket帧
            const combinedData = new Uint8Array(headerArray.length + dataArray.length);
            combinedData.set(headerArray, 0);
            combinedData.set(dataArray, headerArray.length);
            finalData = createWebSocketFrame(combinedData);
        } else {
            // 直接合并数据
            finalData = new Uint8Array(headerArray.length + dataArray.length);
            finalData.set(headerArray, 0);
            finalData.set(dataArray, headerArray.length);
        }
        
        await writer.write(finalData);
        writer.releaseLock();
        
        log(`VLESS proxy handshake sent to ${targetHost}:${targetPort}`);
        return proxySocket;
    } catch (error) {
        console.log('[VLESS-PROXY] Error in VLESS proxy handler:', error.message);
        return null;
    }
}

/**
 * 通过Trojan代理连接
 * @param {Socket} proxySocket - 代理Socket连接
 * @param {URL} proxyUrl - 代理URL对象
 * @param {string} targetHost - 目标主机
 * @param {number} targetPort - 目标端口
 * @param {Uint8Array} initialData - 初始数据
 * @param {function} log - 日志函数
 * @returns {Promise<Socket>} 返回代理Socket
 */
async function connectViaTrojanProxy(proxySocket, proxyUrl, targetHost, targetPort, initialData, log) {
    const password = proxyUrl.username;
    
    // 构建Trojan请求头
    const trojanHeader = buildTrojanHeader(password, targetHost, targetPort);
    
    // 发送Trojan握手和初始数据
    const writer = proxySocket.writable.getWriter();
    
    // Safe data merging without spread operator
    const headerArray = trojanHeader instanceof Uint8Array ? trojanHeader : new Uint8Array(trojanHeader);
    const dataArray = initialData instanceof Uint8Array ? initialData : new Uint8Array(initialData);
    const combinedData = new Uint8Array(headerArray.length + dataArray.length);
    combinedData.set(headerArray, 0);
    combinedData.set(dataArray, headerArray.length);
    
    await writer.write(combinedData);
    writer.releaseLock();
    
    log(`Trojan proxy handshake sent to ${targetHost}:${targetPort}`);
    return proxySocket;
}

/**
 * 构建VLESS协议头
 * @param {string} uuid - 用户UUID
 * @param {string} targetHost - 目标主机
 * @param {number} targetPort - 目标端口
 * @returns {Uint8Array} VLESS协议头字节数组
 */
function buildVlessHeader(uuid, targetHost, targetPort) {
    const uuidBytes = parseUUID(uuid);
    const version = 0;
    const optLength = 0;
    const command = 1; // TCP
    
    // 地址类型和地址
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
        // 域名
        addressType = 2;
        const hostBytes = new TextEncoder().encode(targetHost);
        addressBytes = [hostBytes.length];
        for (let i = 0; i < hostBytes.length; i++) {
            addressBytes.push(hostBytes[i]);
        }
    }
    
    // 端口（大端序）
    const portBytes = [(targetPort >> 8) & 0xff, targetPort & 0xff];
    
    // Build the complete array without spread operator
    const result = [version];
    for (let i = 0; i < uuidBytes.length; i++) {
        result.push(uuidBytes[i]);
    }
    result.push(optLength, command);
    for (let i = 0; i < portBytes.length; i++) {
        result.push(portBytes[i]);
    }
    result.push(addressType);
    for (let i = 0; i < addressBytes.length; i++) {
        result.push(addressBytes[i]);
    }
    return new Uint8Array(result);
}

/**
 * 构建Trojan协议头
 * @param {string} password - Trojan密码
 * @param {string} targetHost - 目标主机
 * @param {number} targetPort - 目标端口
 * @returns {Uint8Array} Trojan协议头字节数组
 */
function buildTrojanHeader(password, targetHost, targetPort) {
    const passwordHash = sha224(password);
    const crlf = [0x0d, 0x0a];
    
    // SOCKS5请求格式
    const cmd = 1; // CONNECT
    const rsv = 0; // 保留字段
    
    // 地址类型和地址
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
        // 域名
        atype = 3;
        const hostBytes = new TextEncoder().encode(targetHost);
        addressBytes = [hostBytes.length];
        for (let i = 0; i < hostBytes.length; i++) {
            addressBytes.push(hostBytes[i]);
        }
    }
    
    // 端口（大端序）
    const portBytes = [(targetPort >> 8) & 0xff, targetPort & 0xff];
    
    // 构建完整的Trojan头
    const passwordBytes = new TextEncoder().encode(passwordHash);
    const socks5Request = [cmd, rsv, atype];
    for (let i = 0; i < addressBytes.length; i++) {
        socks5Request.push(addressBytes[i]);
    }
    for (let i = 0; i < portBytes.length; i++) {
        socks5Request.push(portBytes[i]);
    }
    
    // Build final result without spread operator
    const result = [];
    for (let i = 0; i < passwordBytes.length; i++) {
        result.push(passwordBytes[i]);
    }
    for (let i = 0; i < crlf.length; i++) {
        result.push(crlf[i]);
    }
    for (let i = 0; i < socks5Request.length; i++) {
        result.push(socks5Request[i]);
    }
    
    return new Uint8Array(result);
}

/**
 * 解析UUID字符串为字节数组
 * @param {string} uuid - UUID字符串
 * @returns {Uint8Array} UUID字节数组
 */
function parseUUID(uuid) {
    const hex = uuid.replace(/-/g, '');
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return bytes;
}

/**
 * 创建WebSocket二进制帧
 * @param {Uint8Array} data - 要包装的数据
 * @returns {Uint8Array} WebSocket帧
 */
function createWebSocketFrame(data) {
    const dataLength = data.length;
    let frame;
    
    if (dataLength < 126) {
        // 短帧：2字节头部
        frame = new Uint8Array(2 + dataLength);
        frame[0] = 0x82; // FIN=1, opcode=2 (binary)
        frame[1] = dataLength;
        frame.set(data, 2);
    } else if (dataLength < 65536) {
        // 中等帧：4字节头部
        frame = new Uint8Array(4 + dataLength);
        frame[0] = 0x82; // FIN=1, opcode=2 (binary)
        frame[1] = 126;
        frame[2] = (dataLength >> 8) & 0xff;
        frame[3] = dataLength & 0xff;
        frame.set(data, 4);
    } else {
        // 长帧：10字节头部
        frame = new Uint8Array(10 + dataLength);
        frame[0] = 0x82; // FIN=1, opcode=2 (binary)
        frame[1] = 127;
        // 64位长度，但JavaScript只支持53位精度，所以前4字节为0
        frame[2] = 0;
        frame[3] = 0;
        frame[4] = 0;
        frame[5] = 0;
        frame[6] = (dataLength >> 24) & 0xff;
        frame[7] = (dataLength >> 16) & 0xff;
        frame[8] = (dataLength >> 8) & 0xff;
        frame[9] = dataLength & 0xff;
        frame.set(data, 10);
    }
    
    return frame;
}

/**
 * 解析WebSocket帧
 * @param {Uint8Array} frame - WebSocket帧数据
 * @returns {Uint8Array|null} 解析出的数据，如果解析失败返回null
 */
function parseWebSocketFrame(frame) {
    if (frame.length < 2) {
        return null;
    }
    
    const firstByte = frame[0];
    const secondByte = frame[1];
    
    // 检查FIN位和opcode
    const fin = (firstByte & 0x80) === 0x80;
    const opcode = firstByte & 0x0f;
    
    // 只处理二进制帧 (opcode = 2) 或文本帧 (opcode = 1)
    if (opcode !== 1 && opcode !== 2) {
        return null;
    }
    
    // 获取payload长度
    const masked = (secondByte & 0x80) === 0x80;
    let payloadLength = secondByte & 0x7f;
    let offset = 2;
    
    if (payloadLength === 126) {
        if (frame.length < 4) return null;
        payloadLength = (frame[2] << 8) | frame[3];
        offset = 4;
    } else if (payloadLength === 127) {
        if (frame.length < 10) return null;
        // JavaScript只支持53位精度，忽略前4字节
        payloadLength = (frame[6] << 24) | (frame[7] << 16) | (frame[8] << 8) | frame[9];
        offset = 10;
    }
    
    // 处理掩码
    if (masked) {
        if (frame.length < offset + 4) return null;
        const maskKey = frame.slice(offset, offset + 4);
        offset += 4;
        
        if (frame.length < offset + payloadLength) return null;
        const payload = frame.slice(offset, offset + payloadLength);
        
        // 解除掩码
        for (let i = 0; i < payload.length; i++) {
            payload[i] ^= maskKey[i % 4];
        }
        
        return payload;
    } else {
        if (frame.length < offset + payloadLength) return null;
        return frame.slice(offset, offset + payloadLength);
    }
}

