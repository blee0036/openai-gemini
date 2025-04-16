// Cloudflare Worker Entry Point
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Health Check
    if (pathname === '/' && request.method === 'GET') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // List Models Endpoint
    if (pathname === '/v1/models' && request.method === 'GET') {
      return handleModels(request, env);
    }

    // Chat Completions Endpoint
    if (pathname === '/v1/chat/completions' && request.method === 'POST') {
      return handleChatCompletions(request, env);
    }

    return new Response('Not Found', { status: 404 });
  }
};

// --- Configuration ---
const AKASH_CHAT_API_URL = 'https://chat.akash.network/api/chat';
const AKASH_MODELS_API_URL = 'https://chat.akash.network/api/models';
const AKASH_SESSION_API_URL = 'https://chat.akash.network/api/auth/session';
const AKASH_IMAGE_STATUS_API_URL = 'https://chat.akash.network/api/image-status';
const IMAGE_UPLOAD_URL = 'https://api.xinyew.cn/api/jdtc'; // 新野图床 JDTc

// --- Helper Functions ---

/**
 * Generates a pseudo-UUID string (16 hex chars).
 * Uses crypto.randomUUID if available, otherwise a simpler fallback.
 */
function generateSimpleId() {
  if (crypto && crypto.randomUUID) {
    return crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  } else {
    // Fallback for environments without crypto.randomUUID (less common in modern workers)
    return Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  }
}

/**
 * Checks API key if required by environment variable.
 */
async function authenticateRequest(request, env) {
  if (!env.OPENAI_API_KEY) {
    return { authenticated: true, errorResponse: null }; // No key required
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { authenticated: false, errorResponse: new Response(JSON.stringify({ error: 'Missing or invalid Authorization header' }), { status: 401, headers: { 'Content-Type': 'application/json' } }) };
  }

  const token = authHeader.substring(7); // Remove 'Bearer '
  if (token !== env.OPENAI_API_KEY) {
    return { authenticated: false, errorResponse: new Response(JSON.stringify({ error: 'Invalid API key' }), { status: 401, headers: { 'Content-Type': 'application/json' } }) };
  }

  return { authenticated: true, errorResponse: null };
}


/**
 * Fetches a new session cookie from Akash.
 * Note: Directly replicating curl_cffi impersonation isn't possible.
 * We send standard browser-like headers.
 */
async function getAkashCookie() {
  try {
    const response = await fetch(AKASH_SESSION_API_URL, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36', // Mimic browser
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://chat.akash.network/'
      },
      redirect: 'manual', // Important to capture Set-Cookie headers even on redirects
    });

    if (!response.ok && response.status !== 302) { // Allow redirects as they might set cookies
      console.error(`Error fetching cookie: Status ${response.status}`);
      console.error(`Response: ${await response.text()}`);
      return null;
    }

    // Extract cookies
    const setCookieHeaders = response.headers.getAll('Set-Cookie');
    if (!setCookieHeaders || setCookieHeaders.length === 0) {
      console.error('No Set-Cookie header received');
      // Even if no Set-Cookie, maybe the empty session is okay for some requests?
      // Let's return null for now to indicate failure
      return null;
    }

    // Combine cookies into a single string
    const cookies = setCookieHeaders.map(cookie => cookie.split(';')[0]); // Get only name=value part
    const cookieString = cookies.join('; ');

    console.log(`Got cookies: ${cookieString}`);
    return cookieString;

  } catch (error) {
    console.error(`Error fetching cookie: ${error.message}`);
    console.error(error.stack);
    return null;
  }
}

/**
 * Builds common headers for Akash API calls.
 */
function buildAkashHeaders(cookie) {
  return {
    'Content-Type': 'application/json',
    'Cookie': cookie || '', // Use fetched cookie
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    // 'Accept-Encoding': 'gzip, deflate, br', // Let fetch handle encoding
    'Origin': 'https://chat.akash.network',
    'Referer': 'https://chat.akash.network/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    // 'Connection': 'keep-alive', // Let fetch handle connection management
    'Priority': 'u=1, i'
  };
}

/**
 * Uploads a base64 encoded image to the image hosting service.
 */
async function uploadImage(imageBase64, jobId) {
  try {
    console.log(`\n=== Starting image upload for job ${jobId} ===`);

    // 1. Decode Base64
    let base64Data = imageBase64;
    let mimeType = 'image/jpeg'; // Default or detect
    if (imageBase64.startsWith('data:')) {
      const parts = imageBase64.split(',');
      const meta = parts[0].split(':')[1].split(';')[0];
      mimeType = meta || mimeType;
      base64Data = parts[1];
    }

    const byteString = atob(base64Data);
    const ab = new ArrayBuffer(byteString.length);
    const ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
      ia[i] = byteString.charCodeAt(i);
    }
    const blob = new Blob([ab], { type: mimeType });
    console.log(`Decoded image data length: ${blob.size} bytes`);

    // 2. Prepare FormData
    const formData = new FormData();
    const filename = `${jobId}.${mimeType.split('/')[1] || 'jpeg'}`;
    formData.append('file', blob, filename);
    console.log(`Using filename: ${filename}`);

    // 3. Upload
    console.log("Sending request to image host...");
    const response = await fetch(IMAGE_UPLOAD_URL, {
      method: 'POST',
      body: formData,
      // DO NOT set Content-Type header for FormData, fetch does it correctly
    });

    console.log(`Upload response status: ${response.status}`);
    if (!response.ok) {
      console.error(`Upload failed with status ${response.status}`);
      console.error(`Response content: ${await response.text()}`);
      return null;
    }

    const result = await response.json();
    console.log(`Upload response: ${JSON.stringify(result)}`);

    if (result.errno === 0 && result.data && result.data.url) {
      console.log(`Successfully got image URL: ${result.data.url}`);
      return result.data.url;
    } else {
      console.error(`Upload failed: ${result.message || 'Unknown error from image host'}`);
      return null;
    }
  } catch (error) {
    console.error(`Error in uploadImage: ${error.message}`);
    console.error(error.stack);
    return null;
  }
}


/**
 * Checks image generation status and uploads the result.
 */
async function checkImageStatusAndUpload(jobId, cookie, headers) {
  const maxRetries = 30; // ~30 seconds total wait time
  const initialDelay = 1000; // 1 second

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      console.log(`\nImage Status Check Attempt ${attempt + 1}/${maxRetries} for job ${jobId}`);
      const statusUrl = `${AKASH_IMAGE_STATUS_API_URL}?ids=${jobId}`;
      const response = await fetch(statusUrl, { headers });

      console.log(`Image Status response code: ${response.status}`);
      if (!response.ok) {
        console.error(`Failed to check image status: ${response.status}`);
        await new Promise(resolve => setTimeout(resolve, initialDelay)); // Wait before retrying on network error
        continue;
      }

      const statusData = await response.json();

      if (statusData && Array.isArray(statusData) && statusData.length > 0) {
        const jobInfo = statusData[0];
        const status = jobInfo?.status;
        console.log(`Job status: ${status}`);

        if (status === "completed") {
          const result = jobInfo.result; // Base64 string
          if (result && !result.startsWith("Failed")) {
            console.log("Got valid result, attempting upload...");
            const imageUrl = await uploadImage(result, jobId); // Call upload function
            if (imageUrl) {
              console.log(`Successfully uploaded image: ${imageUrl}`);
              return imageUrl;
            } else {
              console.log("Image upload failed after completion.");
              return null; // Upload failed
            }
          } else {
            console.log("Invalid or failed result received from Akash.");
            return null; // Job completed but failed
          }
        } else if (status === "failed") {
          console.log(`Job ${jobId} failed.`);
          return null; // Job explicitly failed
        }
        // If status is pending or something else, wait and loop again
      } else {
        console.log("Unexpected status response format or empty data.");
      }

    } catch (error) {
      console.error(`Error checking image status: ${error.message}`);
      console.error(error.stack);
      // Don't immediately fail, wait and retry
    }

    // Wait before the next attempt
    await new Promise(resolve => setTimeout(resolve, initialDelay));
  }

  console.log(`Timeout waiting for job ${jobId} to complete.`);
  return null; // Timeout
}


// --- Endpoint Handlers ---

/**
 * Handles /v1/models
 */
async function handleModels(request, env) {
  // 1. Authentication
  const authResult = await authenticateRequest(request, env);
  if (!authResult.authenticated) {
    return authResult.errorResponse;
  }

  let cookie;
  try {
    // 2. Get Cookie (essential for this endpoint)
    cookie = await getAkashCookie();
    if (!cookie) {
      return new Response(JSON.stringify({ error: 'Failed to retrieve session cookie from Akash' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
    }

    // 3. Fetch Models from Akash
    const headers = buildAkashHeaders(cookie);
    const response = await fetch(AKASH_MODELS_API_URL, { headers });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Akash models API error: ${response.status} - ${errorText}`);
      return new Response(JSON.stringify({ error: `Failed to fetch models from Akash: ${response.status}` }), { status: response.status, headers: { 'Content-Type': 'application/json' } });
    }

    const akashResponse = await response.json();
    console.log(`Akash API response: ${JSON.stringify(akashResponse)}`);

    // 4. Transform to OpenAI Format
    let modelsList = [];
    if (Array.isArray(akashResponse)) {
      modelsList = akashResponse;
    } else if (typeof akashResponse === 'object' && akashResponse !== null && Array.isArray(akashResponse.models)) {
      modelsList = akashResponse.models;
    } else {
      console.error(`Unexpected response format from Akash models API: ${typeof akashResponse}`);
      // Return empty list or error? Let's return an empty list for now.
    }


    const currentTime = Math.floor(Date.now() / 1000);
    const openaiModels = {
      object: "list",
      data: modelsList.map(model => {
        const modelId = typeof model === 'object' && model !== null ? model.id : model;
        return {
          id: modelId,
          object: "model",
          created: currentTime,
          owned_by: "akash", // Or determine more accurately if possible
          permission: [{
            id: `modelperm-${modelId}`,
            object: "model_permission",
            created: currentTime,
            allow_create_engine: false,
            allow_sampling: true,
            allow_logprobs: true,
            allow_search_indices: false,
            allow_view: true,
            allow_fine_tuning: false,
            organization: "*",
            group: null,
            is_blocking: false
          }],
          root: modelId,
          parent: null
        };
      })
    };

    return new Response(JSON.stringify(openaiModels), {
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error(`Error in handleModels: ${error.message}`);
    console.error(error.stack);
    return new Response(JSON.stringify({ error: 'Internal server error while fetching models.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

/**
 * Handles /v1/chat/completions
 */
async function handleChatCompletions(request, env) {
  // 1. Authentication
  const authResult = await authenticateRequest(request, env);
  if (!authResult.authenticated) {
    return authResult.errorResponse;
  }

  let requestData;
  try {
    requestData = await request.json();
    console.log(`Chat request data: ${JSON.stringify(requestData)}`);
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  let cookie;
  try {
    // 2. Get Cookie (always fetch new one as requested)
    cookie = await getAkashCookie();
    if (!cookie) {
      console.error('Proceeding without cookie after failed attempt...');
      // Depending on the API, this might fail downstream. Consider returning error:
      // return new Response(JSON.stringify({ error: 'Failed to retrieve session cookie from Akash' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
    }

    // 3. Prepare Request for Akash
    const chatId = generateSimpleId();
    const model = requestData.model || "DeepSeek-R1"; // Default model
    const stream = requestData.stream || (model === "AkashGen"); // Stream AkashGen by default

    const akashData = {
      id: chatId,
      messages: requestData.messages || [],
      model: model,
      system: requestData.system_message || "You are a helpful assistant.", // Use system_message field if present
      temperature: requestData.temperature ?? 0.6, // Use ?? for default value
      topP: requestData.top_p ?? 0.95
    };

    const headers = buildAkashHeaders(cookie);

    console.log(`Sending request to Akash with headers: ${JSON.stringify(headers)}`);
    console.log(`Request data: ${JSON.stringify(akashData)}`);
    console.log(`stream requested: ${stream}`);

    // 4. Make Request to Akash Chat API
    const response = await fetch(AKASH_CHAT_API_URL, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(akashData),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Akash chat API error: ${response.status} - ${errorText}`);
      return new Response(JSON.stringify({ error: `Akash API request failed: ${response.status}`, details: errorText }), { status: response.status, headers: { 'Content-Type': 'application/json' } });
    }

    // 5. Handle Response (Streaming or Non-Streaming)
    if (stream && response.body) {
      // Streaming response
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();

      // Process the stream from Akash in the background
      streamAkashResponse(response.body, writer, encoder, decoder, chatId, model, headers, cookie);

      return new Response(readable, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });

    } else {
      // Non-streaming response
      const responseText = await response.text();
      // Attempt to parse the non-streamed response (this format might be unreliable)
      let content = '';
      // Regex to find 0:"..." patterns, handling escaped quotes
      const matches = responseText.matchAll(/0:"((?:\\.|[^"\\])*)"/g);
      for (const match of matches) {
        // Simple unescaping for \n and \"
        content += match[1].replace(/\\n/g, '\n').replace(/\\"/g, '"');
      }

      // Check if content extraction failed and maybe try a simpler line-based approach
      if (!content && responseText) {
        console.warn("Regex extraction failed for non-streamed response, trying line split.");
        responseText.split('\n').forEach(line => {
          if(line.startsWith('0:')) {
            try {
              let data = line.substring(2);
              if(data.startsWith('"') && data.endsWith('"')) {
                data = data.slice(1,-1);
              }
              content += JSON.parse(`"${data}"`); // More robust parsing of JSON string content
            } catch(e) {
              console.error(`Error parsing line fragment: ${line}`, e);
            }
          }
        });
      }

      const completionData = {
        id: `chatcmpl-${chatId}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: model,
        choices: [{
          index: 0,
          message: {
            role: "assistant",
            content: content,
          },
          finish_reason: "stop",
        }],
        usage: { // Provide dummy usage stats as they are not available
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0,
        }
      };

      return new Response(JSON.stringify(completionData), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

  } catch (error) {
    console.error(`Error in handleChatCompletions: ${error.message}`);
    console.error(error.stack);
    return new Response(JSON.stringify({ error: 'Internal server error during chat completion.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

/**
 * Processes the SSE stream from Akash and transforms it into OpenAI format.
 */
async function streamAkashResponse(readableStream, writer, encoder, decoder, chatId, model, imageCheckHeaders, cookie) {
  const reader = readableStream.getReader();
  let buffer = '';
  let contentBuffer = ''; // Accumulate content for potential non-stream use or inspection

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        console.log('Akash stream finished.');
        // If the stream ended without an 'e' or 'd' message, send the final chunk manually
        if (buffer) {
          console.warn("Stream ended with partial data in buffer:", buffer);
        }
        // Ensure a final chunk and DONE signal are sent if not already done
        const finalChunk = {
          id: `chatcmpl-${chatId}`,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: model,
          choices: [{ delta: {}, index: 0, finish_reason: "stop" }]
        };
        await writer.write(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
        await writer.write(encoder.encode('data: [DONE]\n\n'));
        break;
      }

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // Keep the last partial line in buffer

      for (const line of lines) {
        if (!line.trim()) continue;

        try {
          // Basic parsing: type:data
          const separatorIndex = line.indexOf(':');
          if (separatorIndex === -1) {
            console.warn("Skipping malformed line:", line);
            continue;
          }
          const msgType = line.substring(0, separatorIndex);
          let msgData = line.substring(separatorIndex + 1);

          if (msgType === '0') { // Content chunk
            // Handle JSON string decoding carefully ("...\"...")
            if (msgData.startsWith('"') && msgData.endsWith('"')) {
              try {
                // Safest way to decode JSON string content
                msgData = JSON.parse(msgData);
              } catch (e) {
                console.warn("Failed to JSON.parse msgData, fallback to basic replace:", msgData, e);
                // Basic unescaping as fallback (less reliable)
                msgData = msgData.slice(1,-1).replace(/\\"/g, '"').replace(/\\n/g, '\n');
              }
            }
            // Handle escaped newlines even if not quoted JSON style
            msgData = msgData.replace(/\\n/g, '\n');

            // IMAGE GENERATION Handling for AkashGen
            if (model === 'AkashGen' && msgData.includes("<image_generation>")) {
              const imageRegex = /jobId='([^']+)' prompt='([^']+)'/;;
              const match = msgData.match(imageRegex);
              if (match) {
                const jobId = match[1];
                const prompt = match[2];
                console.log(`Detected image generation request: jobId=${jobId}, prompt=${prompt}`);

                // Don't block the text stream. Process image in parallel.
                // Use ctx.waitUntil for background tasks if needed and available
                // Using a simple async call here, might slightly delay subsequent text chunks
                // if the image check is slow, but keeps the main stream flowing.
                processImageGenerationStream(writer, encoder, jobId, prompt, chatId, imageCheckHeaders, cookie);
                continue; // Skip sending the raw <image_generation> tag
              }
            }

            // Send standard text chunk
            contentBuffer += msgData; // Keep accumulating content
            const chunk = {
              id: `chatcmpl-${chatId}`,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: model,
              choices: [{ delta: { content: msgData }, index: 0, finish_reason: null }]
            };
            await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));

          } else if (msgType === 'e' || msgType === 'd') { // End of stream markers
            console.log(`Received end marker: ${msgType}`);
            const finalChunk = {
              id: `chatcmpl-${chatId}`,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: model,
              choices: [{ delta: {}, index: 0, finish_reason: "stop" }]
            };
            await writer.write(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
            await writer.write(encoder.encode('data: [DONE]\n\n'));
            // No 'break' here, let reader.read() return done:true
          } else {
            console.log(`Unknown message type '${msgType}': ${line}`);
          }
        } catch(parseError) {
          console.error("Error processing line:", line, parseError);
        }
      }
    }
  } catch (error) {
    console.error(`Error reading or processing Akash stream: ${error.message}`);
    console.error(error.stack);
    try {
      // Try to signal error downstream if possible
      const errorChunk = {
        error: `Stream processing error: ${error.message}`
      }
      await writer.write(encoder.encode(`data: ${JSON.stringify(errorChunk)}\n\n`));
      await writer.write(encoder.encode('data: [DONE]\n\n')); // Still send DONE
    } catch (writeError) {
      console.error("Error writing error chunk:", writeError);
    }
  } finally {
    console.log('Closing stream writer.');
    await writer.close();
  }
}


/**
 * Handles the asynchronous process of checking image status and sending results back via the stream writer.
 */
async function processImageGenerationStream(writer, encoder, jobId, prompt, chatId, headers, cookie) {
  const startTime = Date.now();

  // 1. Send Thinking Message Chunk
  let thinkMsg = `<think>\n🎨 Generating image...\n\nPrompt: ${prompt}\n</think>`;
  const thinkChunk = {
    id: `chatcmpl-${chatId}-think`,
    object: "chat.completion.chunk",
    created: Math.floor(startTime / 1000),
    model: "AkashGen",
    choices: [{ delta: { content: thinkMsg }, index: 0, finish_reason: null }]
  };
  try {
    await writer.write(encoder.encode(`data: ${JSON.stringify(thinkChunk)}\n\n`));
  } catch (e) { console.error("Error writing think chunk:", e); return; } // Stop if writer fails

  // 2. Check Status and Upload (using the shared cookie and headers)
  const imageUrl = await checkImageStatusAndUpload(jobId, cookie, headers);
  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(1);


  // 3. Send Result Message Chunk
  let finalContent = '';
  if (imageUrl) {
    // Send thinking time update *before* the image
    const durationMsg = `<think>\n🤔 Thinking finished in ${duration}s.\n</think>\n\n`;
    const durationChunk = {
      id: `chatcmpl-${chatId}-duration`,
      object: "chat.completion.chunk",
      created: Math.floor(endTime / 1000),
      model: "AkashGen",
      choices: [{ delta: { content: durationMsg }, index: 0, finish_reason: null }]
    };
    try { await writer.write(encoder.encode(`data: ${JSON.stringify(durationChunk)}\n\n`)); }
    catch (e) { console.error("Error writing duration chunk:", e); return; }

    // Then send the image link
    finalContent = `![Generated Image](${imageUrl})`;
  } else {
    finalContent = `\n\n*Image generation or upload failed after ${duration}s.*`;
  }

  const resultChunk = {
    id: `chatcmpl-${chatId}-image`,
    object: "chat.completion.chunk",
    created: Math.floor(endTime / 1000),
    model: "AkashGen",
    choices: [{ delta: { content: finalContent }, index: 0, finish_reason: null }] // Finish reason is null, let main loop handle stop
  };

  try {
    await writer.write(encoder.encode(`data: ${JSON.stringify(resultChunk)}\n\n`));
  } catch (e) { console.error("Error writing result chunk:", e); }
}

