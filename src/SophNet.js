/**
 * @typedef {Object} Env
 */

export default {
  /**
   * @param {Request} request
   * @param {Env} env
   * @param {ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    return handleRequest(request);
  },
};


const SOPHNET_BASE_URL = "https://www.sophnet.com/api";
const PROJECT_UUID = "Ar79PWUQUAhjJOja2orHs";

async function getAnonymousToken() {
  try {
    const response = await nativeFetch(`${SOPHNET_BASE_URL}/sys/login/anonymous`, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get token: ${response.status}`);
    }

    const data = await response.json();
    return data.result.anonymousToken;
  } catch (error) {
    console.error("Error getting anonymous token:", error);
    throw error;
  }
}

async function getModels(token) {
  try {
    const response = await nativeFetch(
      `${SOPHNET_BASE_URL}/public/playground/models?projectUuid=${PROJECT_UUID}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
          "Authorization": `Bearer anon-${token}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get models: ${response.status}`);
    }

    const data = await response.json();
    return data.result;
  } catch (error) {
    console.error("Error getting models:", error);
    throw error;
  }
}

function transformModelsToOpenAIFormat(models) {
  return {
    object: "list",
    data: models.map((model) => ({
      id: model.modelFamily,
      object: "model",
      created: Date.now(),
      owned_by: "sophnet",
      permission: [{
        id: `modelperm-${model.id}`,
        object: "model_permission",
        created: Date.now(),
        allow_create_engine: false,
        allow_sampling: true,
        allow_logprobs: false,
        allow_search_indices: false,
        allow_view: true,
        allow_fine_tuning: false,
        organization: "*",
        group: null,
        is_blocking: false,
      }],
      root: model.modelFamily,
      parent: null,
    })),
  };
}

async function handleChatCompletions(token, requestBody, stream) {
  const sophNetBody = {
    temperature: requestBody.temperature || 1,
    top_p: requestBody.top_p || 1,
    frequency_penalty: requestBody.frequency_penalty || 0,
    presence_penalty: requestBody.presence_penalty || 0,
    max_tokens: requestBody.max_tokens || 2048,
    webSearchEnable: false,
    stop: requestBody.stop || [],
    stream: stream.toString(),
    model_id: requestBody.model,
    messages: requestBody.messages,
  };

  const response = await nativeFetch(
    `${SOPHNET_BASE_URL}/open-apis/projects/${PROJECT_UUID}/chat/completions`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer anon-${token}`,
        "Accept": stream ? "text/event-stream" : "application/json",
      },
      body: JSON.stringify(sophNetBody),
    }
  );

  if (!response.ok) {
    throw new Error(`Chat completion failed: ${response.status}`);
  }

  return response;
}

async function* transformStreamResponse(readableStream) {
  const reader = readableStream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.trim() === "" || !line.startsWith("data:")) continue;

        const data = line.substring(5).trim();
        if (data === "[DONE]") {
          yield "data: [DONE]\n\n";
          continue;
        }

        try {
          const sophNetEvent = JSON.parse(data);
          const openAIEvent = {
            id: sophNetEvent.id || `chatcmpl-${Date.now()}`,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: sophNetEvent.model || "sophnet-model",
            choices: [
              {
                index: 0,
                delta: {
                  content: sophNetEvent.choices?.[0]?.delta?.content || "",
                },
                finish_reason: sophNetEvent.choices?.[0]?.finish_reason || null,
              },
            ],
          };

          yield `data: ${JSON.stringify(openAIEvent)}\n\n`;
        } catch (e) {
          console.error("Error parsing event:", e, "Line:", line);
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

async function transformNonStreamResponse(response) {
  const sophNetResponse = await response.json();
  return {
    id: sophNetResponse.id || `chatcmpl-${Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: sophNetResponse.model || "sophnet-model",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: sophNetResponse.choices?.[0]?.message?.content || "",
        },
        finish_reason: sophNetResponse.choices?.[0]?.finish_reason || "stop",
      },
    ],
    usage: sophNetResponse.usage || {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

async function handleRequest(req) {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  let token;
  try {
    token = await getAnonymousToken();
  } catch (error) {
    return new Response(
      JSON.stringify({ error: "Failed to get token", details: error.message }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      }
    );
  }

  try {
    if (path === "/v1/models" && req.method === "GET") {
      const models = await getModels(token);
      const openAIModels = transformModelsToOpenAIFormat(models);
      return new Response(JSON.stringify(openAIModels), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    } else if (path === "/v1/chat/completions" && req.method === "POST") {
      const requestBody = await req.json();
      const stream = requestBody.stream === true;
      const sophNetResponse = await handleChatCompletions(token, requestBody, stream);

      if (stream) {
        const transformedStream = new ReadableStream({
          async start(controller) {
            try {
              for await (const chunk of transformStreamResponse(sophNetResponse.body)) {
                controller.enqueue(new TextEncoder().encode(chunk));
              }
              controller.close();
            } catch (error) {
              controller.error(error);
            }
          },
        });

        return new Response(transformedStream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
          },
        });
      } else {
        const transformedResponse = await transformNonStreamResponse(sophNetResponse);
        return new Response(JSON.stringify(transformedResponse), {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
    } else {
      return new Response(
        JSON.stringify({ error: "Not found", message: "Endpoint not supported" }),
        {
          status: 404,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }
  } catch (error) {
    return new Response(
      JSON.stringify({ error: "Internal server error", message: error.message }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      }
    );
  }
}

import { connect } from "cloudflare:sockets";

// Global configuration including the authentication token, default destination URL, and debug mode flag
const CONFIG = {
  AUTH_TOKEN: "image",
  DEFAULT_DST_URL: "https://example.com/",
  DEBUG_MODE: false,
};

// Update global configuration from environment variables (prioritizing environment values)
function updateConfigFromEnv(env) {
  if (!env) return;
  for (const key of Object.keys(CONFIG)) {
    if (key in env) {
      if (typeof CONFIG[key] === 'boolean') {
        CONFIG[key] = env[key] === 'true';
      } else {
        CONFIG[key] = env[key];
      }
    }
  }
}

// Define text encoder and decoder for converting between strings and byte arrays
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Filter out HTTP headers that should not be forwarded (ignore headers: host, accept-encoding, cf-*)
const HEADER_FILTER_RE = /^(host|accept-encoding|cf-)/i;

// Define the debug log output function based on the debug mode setting
const log = CONFIG.DEBUG_MODE
  ? (message, data = "") => console.log(`[DEBUG] ${message}`, data)
  : () => {};

// Concatenate multiple Uint8Arrays into a single new Uint8Array
function concatUint8Arrays(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Parse HTTP response headers, returning the status code, status text, headers, and the header section's end position
function parseHttpHeaders(buff) {
  const text = decoder.decode(buff);
  // Look for the end of HTTP headers indicated by "\r\n\r\n"
  const headerEnd = text.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;
  const headerSection = text.slice(0, headerEnd).split("\r\n");
  const statusLine = headerSection[0];
  // Match the HTTP status line, e.g., "HTTP/1.1 200 OK"
  const statusMatch = statusLine.match(/HTTP\/1\.[01] (\d+) (.*)/);
  if (!statusMatch) throw new Error(`Invalid status line: ${statusLine}`);
  const headers = new Headers();
  // Parse the response headers
  for (let i = 1; i < headerSection.length; i++) {
    const line = headerSection[i];
    const idx = line.indexOf(": ");
    if (idx !== -1) {
      headers.append(line.slice(0, idx), line.slice(idx + 2));
    }
  }
  return { status: Number(statusMatch[1]), statusText: statusMatch[2], headers, headerEnd };
}

// Read data from the reader until a double CRLF (indicating the end of HTTP headers) is encountered
async function readUntilDoubleCRLF(reader) {
  let respText = "";
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      respText += decoder.decode(value, { stream: true });
      if (respText.includes("\r\n\r\n")) break;
    }
    if (done) break;
  }
  return respText;
}

// Async generator: read chunked HTTP response data chunks and yield each chunk sequentially
async function* readChunks(reader, buff = new Uint8Array()) {
  while (true) {
    // Look for the position of the CRLF separator in the existing buffer
    let pos = -1;
    for (let i = 0; i < buff.length - 1; i++) {
      if (buff[i] === 13 && buff[i + 1] === 10) {
        pos = i;
        break;
      }
    }
    // If not found, continue reading more data to fill the buffer
    if (pos === -1) {
      const { value, done } = await reader.read();
      if (done) break;
      buff = concatUint8Arrays(buff, value);
      continue;
    }
    // Parse the chunk size (in hexadecimal format)
    const size = parseInt(decoder.decode(buff.slice(0, pos)), 16);
    log("Read chunk size", size);
    // A size of 0 indicates the end of chunks
    if (!size) break;
    // Remove the parsed size part and the following CRLF from the buffer
    buff = buff.slice(pos + 2);
    // Ensure the buffer contains the complete chunk (including the trailing CRLF)
    while (buff.length < size + 2) {
      const { value, done } = await reader.read();
      if (done) throw new Error("Unexpected EOF in chunked encoding");
      buff = concatUint8Arrays(buff, value);
    }
    // Yield the chunk data (excluding the trailing CRLF)
    yield buff.slice(0, size);
    buff = buff.slice(size + 2);
  }
}

// Parse the complete HTTP response, handling the response body data based on transfer mode (chunked or fixed-length)
async function parseResponse(reader) {
  let buff = new Uint8Array();
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      buff = concatUint8Arrays(buff, value);
      const parsed = parseHttpHeaders(buff);
      if (parsed) {
        const { status, statusText, headers, headerEnd } = parsed;
        const isChunked = headers.get("transfer-encoding")?.includes("chunked");
        const contentLength = parseInt(headers.get("content-length") || "0", 10);
        const data = buff.slice(headerEnd + 4);
        // Distribute the response body data via a ReadableStream
        return new Response(
          new ReadableStream({
            async start(ctrl) {
              try {
                if (isChunked) {
                  log("Using chunked transfer mode");
                  // Chunked transfer mode: read and enqueue each chunk sequentially
                  for await (const chunk of readChunks(reader, data)) {
                    ctrl.enqueue(chunk);
                  }
                } else {
                  log("Using fixed-length transfer mode", { contentLength });
                  let received = data.length;
                  if (data.length) ctrl.enqueue(data);
                  // Fixed-length mode: read the specified number of bytes based on content-length
                  while (received < contentLength) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    received += value.length;
                    ctrl.enqueue(value);
                  }
                }
                ctrl.close();
              } catch (err) {
                log("Error parsing response", err);
                ctrl.error(err);
              }
            },
          }),
          { status, statusText, headers }
        );
      }
    }
    if (done) break;
  }
  throw new Error("Unable to parse response headers");
}

// Generate a random Sec-WebSocket-Key required for the WebSocket handshake
function generateWebSocketKey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

// Pack a text message into a WebSocket frame (currently supports only text frames with payloads not too large)
function packTextFrame(payload) {
  const FIN_AND_OP = 0x81; // FIN flag and text frame opcode
  const maskBit = 0x80; // Mask bit (must be set to 1 for client-sent messages)
  const len = payload.length;
  let header;
  if (len < 126) {
    header = new Uint8Array(2);
    header[0] = FIN_AND_OP;
    header[1] = maskBit | len;
  } else if (len < 65536) {
    header = new Uint8Array(4);
    header[0] = FIN_AND_OP;
    header[1] = maskBit | 126;
    header[2] = (len >> 8) & 0xff;
    header[3] = len & 0xff;
  } else {
    throw new Error("Payload too large");
  }
  // Generate a 4-byte random mask
  const mask = new Uint8Array(4);
  crypto.getRandomValues(mask);
  const maskedPayload = new Uint8Array(len);
  // Apply the mask to the payload
  for (let i = 0; i < len; i++) {
    maskedPayload[i] = payload[i] ^ mask[i % 4];
  }
  // Concatenate the frame header, mask, and masked payload
  return concatUint8Arrays(header, mask, maskedPayload);
}

// Class for parsing and reassembling WebSocket frames, supporting fragmented messages
class SocketFramesReader {
  constructor(reader) {
    this.reader = reader;
    this.buffer = new Uint8Array();
    this.fragmentedPayload = null;
    this.fragmentedOpcode = null;
  }
  // Ensure that the buffer has enough bytes for parsing
  async ensureBuffer(length) {
    while (this.buffer.length < length) {
      const { value, done } = await this.reader.read();
      if (done) return false;
      this.buffer = concatUint8Arrays(this.buffer, value);
    }
    return true;
  }
  // Parse the next WebSocket frame and handle fragmentation (opcode 0 indicates continuation)
  async nextFrame() {
    while (true) {
      if (!(await this.ensureBuffer(2))) return null;
      const first = this.buffer[0],
        second = this.buffer[1],
        fin = (first >> 7) & 1,
        opcode = first & 0x0f,
        isMasked = (second >> 7) & 1;
      let payloadLen = second & 0x7f,
        offset = 2;
      // If payload length is 126, parse the next two bytes for the actual length
      if (payloadLen === 126) {
        if (!(await this.ensureBuffer(offset + 2))) return null;
        payloadLen = (this.buffer[offset] << 8) | this.buffer[offset + 1];
        offset += 2;
      } else if (payloadLen === 127) {
        throw new Error("127 length mode is not supported");
      }
      let mask;
      if (isMasked) {
        if (!(await this.ensureBuffer(offset + 4))) return null;
        mask = this.buffer.slice(offset, offset + 4);
        offset += 4;
      }
      if (!(await this.ensureBuffer(offset + payloadLen))) return null;
      let payload = this.buffer.slice(offset, offset + payloadLen);
      if (isMasked && mask) {
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= mask[i % 4];
        }
      }
      // Remove the processed bytes from the buffer
      this.buffer = this.buffer.slice(offset + payloadLen);
      // Opcode 0 indicates a continuation frame: concatenate the fragmented data
      if (opcode === 0) {
        if (this.fragmentedPayload === null)
          throw new Error("Received continuation frame without initiation");
        this.fragmentedPayload = concatUint8Arrays(this.fragmentedPayload, payload);
        if (fin) {
          const completePayload = this.fragmentedPayload;
          const completeOpcode = this.fragmentedOpcode;
          this.fragmentedPayload = this.fragmentedOpcode = null;
          return { fin: true, opcode: completeOpcode, payload: completePayload };
        }
      } else {
        // If there is fragmented data but the current frame is not a continuation, reset the fragmentation state
        if (!fin) {
          this.fragmentedPayload = payload;
          this.fragmentedOpcode = opcode;
          continue;
        } else {
          if (this.fragmentedPayload) {
            this.fragmentedPayload = this.fragmentedOpcode = null;
          }
          return { fin, opcode, payload };
        }
      }
    }
  }
}

// Forward HTTP requests or WebSocket handshake and data based on the request type
async function nativeFetch(dstUrl, req) {
  // Clean up the headers by removing those that match the filter criteria
  const cleanedHeaders = new Headers();
  const headers = new Headers(req.headers); // 包装成Headers对象
  for (const [k, v] of headers) {
    if (!HEADER_FILTER_RE.test(k)) {
      cleanedHeaders.set(k, v);
    }
  }

  // Check if the request is a WebSocket request
  const upgradeHeader = headers.get("Upgrade")?.toLowerCase();
  const isWebSocket = upgradeHeader === "websocket";
  const targetUrl = new URL(dstUrl);

  if (isWebSocket) {
    // If the target URL does not support the WebSocket protocol, return an error response
    if (!/^wss?:\/\//i.test(dstUrl)) {
      return new Response("Target does not support WebSocket", { status: 400 });
    }
    const isSecure = targetUrl.protocol === "wss:";
    const port = targetUrl.port || (isSecure ? 443 : 80);
    // Establish a raw socket connection to the target server
    const socket = await connect(
      { hostname: targetUrl.hostname, port: Number(port) },
      { secureTransport: isSecure ? "on" : "off" }
    );

    // Generate the key required for the WebSocket handshake
    const key = generateWebSocketKey();

    // Construct the HTTP headers required for the handshake
    cleanedHeaders.set('Host', targetUrl.hostname);
    cleanedHeaders.set('Connection', 'Upgrade');
    cleanedHeaders.set('Upgrade', 'websocket');
    cleanedHeaders.set('Sec-WebSocket-Version', '13');
    cleanedHeaders.set('Sec-WebSocket-Key', key);

    // Assemble the HTTP request data for the WebSocket handshake
    const handshakeReq =
      `GET ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\n` +
      Array.from(cleanedHeaders.entries())
        .map(([k, v]) => `${k}: ${v}`)
        .join('\r\n') +
      '\r\n\r\n';

    log("Sending WebSocket handshake request", handshakeReq);
    const writer = socket.writable.getWriter();
    await writer.write(encoder.encode(handshakeReq));

    const reader = socket.readable.getReader();
    const handshakeResp = await readUntilDoubleCRLF(reader);
    log("Received handshake response", handshakeResp);
    // Verify that the handshake response indicates a 101 Switching Protocols status
    if (
      !handshakeResp.includes("101") ||
      !handshakeResp.includes("Switching Protocols")
    ) {
      throw new Error("WebSocket handshake failed: " + handshakeResp);
    }

    // Create an internal WebSocketPair
    const [client, server] = new WebSocketPair();
    client.accept();
    // Establish bidirectional frame relaying between the client and the remote socket
    relayWebSocketFrames(client, socket, writer, reader);
    return new Response(null, { status: 101, webSocket: server });
  } else {
// 处理标准HTTP请求
    cleanedHeaders.set("Host", targetUrl.hostname);
    cleanedHeaders.set("accept-encoding", "identity");

    const port = targetUrl.protocol === "https:" ? 443 : 80;
    const socket = await connect(
      { hostname: targetUrl.hostname, port },
      { secureTransport: targetUrl.protocol === "https:" ? "on" : "off" }
    );
    const writer = socket.writable.getWriter();

    // 新增：处理请求体并设置Content-Length
    let requestBody;
    if (req.body) {
      if (typeof req.body === 'string') {
        requestBody = encoder.encode(req.body);
      } else {
        // 收集所有块并合并
        const chunks = [];
        for await (const chunk of req.body) {
          chunks.push(typeof chunk === 'string' ? encoder.encode(chunk) : chunk);
        }
        const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
        requestBody = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
          requestBody.set(chunk, offset);
          offset += chunk.length;
        }
      }
      cleanedHeaders.set('Content-Length', requestBody.length.toString());
    } else {
      cleanedHeaders.set('Content-Length', '0');
    }

    // 构造请求行和头部
    const requestLine =
      `${req.method} ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\n` +
      Array.from(cleanedHeaders.entries())
        .map(([k, v]) => `${k}: ${v}`)
        .join("\r\n") +
      "\r\n\r\n";
    log("Sending request", requestLine);
    await writer.write(encoder.encode(requestLine));

    // 发送请求体
    if (requestBody) {
      await writer.write(requestBody);
    }

    // 解析并返回响应
    return await parseResponse(socket.readable.getReader());
  }
}

// Relay WebSocket frames bidirectionally between the client and the remote socket
function relayWebSocketFrames(ws, socket, writer, reader) {
  // Listen for messages from the client, package them into frames, and send them to the remote socket
  ws.addEventListener("message", async (event) => {
    let payload;
    if (typeof event.data === "string") {
      payload = encoder.encode(event.data);
    } else if (event.data instanceof ArrayBuffer) {
      payload = new Uint8Array(event.data);
    } else {
      payload = event.data;
    }
    const frame = packTextFrame(payload);
    try {
      await writer.write(frame);
    } catch (e) {
      log("Remote write error", e);
    }
  });

  // Asynchronously relay WebSocket frames received from the remote to the client
  (async function relayFrames() {
    const frameReader = new SocketFramesReader(reader);
    try {
      while (true) {
        const frame = await frameReader.nextFrame();
        if (!frame) break;
        // Process the data frame based on its opcode
        switch (frame.opcode) {
          case 1: // Text frame
          case 2: // Binary frame
            ws.send(frame.payload);
            break;
          case 8: // Close frame
            log("Received Close frame, closing WebSocket");
            ws.close(1000);
            return;
          default:
            log(`Received unknown frame type, Opcode: ${frame.opcode}`);
        }
      }
    } catch (e) {
      log("Error reading remote frame", e);
    } finally {
      ws.close();
      writer.releaseLock();
      socket.close();
    }
  })();

  // When the client WebSocket closes, also close the remote socket connection
  ws.addEventListener("close", () => socket.close());
}
