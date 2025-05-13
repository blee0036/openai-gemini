// ====================================================================================
// Cloudflare Worker Code for SophNet API Proxy (OpenAI Compatible)
// ====================================================================================

// bind SOPHNET_KV !!!
// bind SOPHNET_KV !!!
// bind SOPHNET_KV !!!

// Cloudflare Worker Entrypoint
export default {
  /**
   * @param {Request} request
   * @param {Env} env
   * @param {ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  },
};


const SOPHNET_BASE_URL = "https://www.sophnet.com/api";
const PROJECT_UUID = "Ar79PWUQUAhjJOja2orHs"; // Replace with your actual Project UUID if different
const TOKEN_KEY = "sophnet_anonymous_token"; // Key used in KV storage
const MAX_RETRIES = 5; // Max retries for API calls
const INITIAL_RETRY_DELAY_MS = 100; // Initial delay for retries (ms)
const MAX_RETRY_DELAY_MS = 5000; // Maximum delay for retries (ms)

// ====================================================================================
// Helper Functions
// ====================================================================================

/**
 * Generates a random User-Agent string.
 * @returns {string} A random User-Agent string.
 */
function getRandomUserAgent() {
  const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.44",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
  ];
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

/**
 * Calculates exponential backoff delay with jitter.
 * @param {number} retryCount - The current retry attempt number (0-indexed).
 * @returns {number} The delay in milliseconds.
 */
function getExponentialBackoffDelay(retryCount) {
  const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, retryCount);
  const jitter = Math.random() * INITIAL_RETRY_DELAY_MS; // Add random jitter
  return Math.min(delay + jitter, MAX_RETRY_DELAY_MS);
}

/**
 * Pauses execution for a specified duration.
 * @param {number} ms - The duration to sleep in milliseconds.
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculates the TTL (Time To Live) in seconds for KV storage based on an expiry date string.
 * Ensures the TTL is at least 60 seconds (Cloudflare KV minimum).
 * @param {string} expiresIsoString - The ISO 8601 format date string for expiration.
 * @returns {number} The TTL in seconds.
 */
function calculateExpirationTtl(expiresIsoString) {
  try {
    const expiresDate = new Date(expiresIsoString);
    const now = new Date();
    const ttlSeconds = Math.floor((expiresDate.getTime() - now.getTime()) / 1000);
    // Ensure ttl is positive and meets Cloudflare's minimum requirement
    return Math.max(60, ttlSeconds);
  } catch (e) {
    console.error("Error calculating TTL from expiry string:", expiresIsoString, e);
    // Default to a reasonable TTL (e.g., 1 hour) if calculation fails
    return 3600;
  }
}

/**
 * Converts a number to its superscript representation.
 * @param {number} num - The number to convert.
 * @returns {string} The superscript string.
 */
function convertToSuperscript(num) {
  const normalDigits = '0123456789';
  const superscriptDigits = '⁰¹²³⁴⁵⁶⁷⁸⁹';

  return num.toString()
    .split('')
    .map(char => {
      const index = normalDigits.indexOf(char);
      return index !== -1 ? superscriptDigits[index] : char;
    })
    .join('');
}

// ====================================================================================
// KV Storage Functions (Cloudflare Workers KV)
// ====================================================================================

/**
 * Retrieves the token information from Cloudflare Workers KV.
 * Requires the KV namespace binding `SOPHNET_KV`.
 * @returns {Promise<object|null>} The token info { token: string, expires: string } or null if not found/error.
 */
async function getTokenFromKV(env) {
  try {
    const tokenInfo = await env.SOPHNET_KV.get(TOKEN_KEY, { type: "json" });
    return tokenInfo;
  } catch (error) {
    console.error("Error getting token from KV:", error);
    return null;
  }
}

async function invalidToken(env) {
  await env.SOPHNET_KV.delete(TOKEN_KEY)
}

/**
 * Stores the token information into Cloudflare Workers KV with an expiration TTL.
 * Requires the KV namespace binding `SOPHNET_KV`.
 * @param {string} token - The anonymous token.
 * @param {string} expires - The ISO 8601 expiration date string.
 * @returns {Promise<void>}
 */
async function storeTokenToKV(token, expires, env) {
  try {
    const ttl = calculateExpirationTtl(expires);
    if (ttl > 59) { // Only store if TTL is valid (at least 60 seconds)
      await env.SOPHNET_KV.put(TOKEN_KEY, JSON.stringify({ token, expires }), { expirationTtl: ttl });
    } else {
      console.warn(`Calculated TTL (${ttl}s) is too short. Token not stored in KV.`);
    }
  } catch (error) {
    console.error("Error storing token to KV:", error);
  }
}

// ====================================================================================
// SophNet API Interaction Functions
// ====================================================================================

/**
 * Fetches a new anonymous token from the SophNet API with retry logic.
 * @param {number} [retryCount=0] - The current retry attempt number.
 * @returns {Promise<string>} The fetched anonymous token.
 * @throws {Error} If fetching fails after maximum retries.
 */
async function getAnonymousToken(env, retryCount = 0) {
  try {
    const response = await nativeFetch(`${SOPHNET_BASE_URL}/sys/login/anonymous`, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "User-Agent": getRandomUserAgent(),
      },
    });

    // Retry on 429 (Too Many Requests) or 5xx server errors
    if ((response.status === 429 || response.status >= 500) && retryCount < MAX_RETRIES) {
      const delay = getExponentialBackoffDelay(retryCount);
      console.warn(`Get token failed with status ${response.status}. Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delay);
      return getAnonymousToken(retryCount + 1);
    }

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Failed to get token: ${response.status} - ${errorText}`);
      throw new Error(`Failed to get token: ${response.status}`);
    }

    const data = await response.json();
    if (data && data.result && data.result.anonymousToken && data.result.expires) {
      await storeTokenToKV(data.result.anonymousToken, data.result.expires, env);
      return data.result.anonymousToken;
    } else {
      console.error("Invalid token response structure:", data);
      throw new Error("Failed to parse anonymous token from response.");
    }
  } catch (error) {
    console.error("Error getting anonymous token:", error);
    // If it's a network error or similar during fetch, retry might still be useful
    if (retryCount < MAX_RETRIES && !(error instanceof Error && error.message.startsWith('Failed to get token'))) {
      const delay = getExponentialBackoffDelay(retryCount);
      console.warn(`Get token network error. Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delay);
      return getAnonymousToken(retryCount + 1);
    }
    throw error; // Rethrow after max retries or for non-retryable errors
  }
}

/**
 * Retrieves a valid token, first trying KV cache, then fetching a new one.
 * @returns {Promise<string>} A valid anonymous token.
 * @throws {Error} If unable to retrieve a valid token.
 */
async function getValidToken(env) {
  const tokenInfo = await getTokenFromKV(env);

  if (tokenInfo && tokenInfo.token && tokenInfo.expires && new Date(tokenInfo.expires) > new Date()) {
    // Optional: Refresh token in the background if it's close to expiring
    // const now = new Date();
    // const expiry = new Date(tokenInfo.expires);
    // if (expiry.getTime() - now.getTime() < SOME_THRESHOLD_MS) {
    //   getAnonymousToken().catch(err => console.error("Background token refresh failed:", err));
    // }
    return tokenInfo.token;
  }
  // Otherwise, fetch a new token
  console.log("No valid token in KV or expired, fetching new token...");
  return await getAnonymousToken(env);
}

/**
 * Fetches the list of available models from the SophNet API with retry and token refresh logic.
 * @param {string} token - A valid anonymous token.
 * @param {number} [retryCount=0] - The current retry attempt number.
 * @returns {Promise<Array<object>>} An array of SophNet model objects.
 * @throws {Error} If fetching fails after maximum retries.
 */
async function getModels(token, retryCount = 0) {
  try {
    const response = await nativeFetch(
      `${SOPHNET_BASE_URL}/public/playground/models?projectUuid=${PROJECT_UUID}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "User-Agent": getRandomUserAgent(),
          "Authorization": `Bearer anon-${token}`,
        },
      }
    );

    // If token is invalid/expired (401/403), refresh token and retry
    if ((response.status === 401 || response.status === 403) && retryCount < MAX_RETRIES) {
      console.log(`Token expired or invalid (${response.status}), refreshing and retrying models request (${retryCount + 1}/${MAX_RETRIES})...`);
      const newToken = await getAnonymousToken(); // Fetch a fresh token
      // Add a small delay before retrying with the new token
      const delay = getExponentialBackoffDelay(retryCount);
      await sleep(delay);
      return await getModels(newToken, retryCount + 1); // Retry with the new token
    }

    // Retry on 429 or 5xx errors
    if ((response.status === 429 || response.status >= 500) && retryCount < MAX_RETRIES) {
      const delay = getExponentialBackoffDelay(retryCount);
      console.warn(`Get models failed with status ${response.status}. Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delay);
      // Retry with the *same* token first. If it fails with 401/403, the logic above will handle refresh.
      return getModels(token, retryCount + 1);
    }


    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Failed to get models: ${response.status} - ${errorText}`);
      throw new Error(`Failed to get models: ${response.status}`);
    }

    const data = await response.json();

    // Optional: Background token refresh after successful request
    // getAnonymousToken().catch(err => console.error("Background token refresh failed:", err));

    return data.result || []; // Return empty array if result is missing
  } catch (error) {
    console.error("Error getting models:", error);
    // If it's a network error or similar during fetch, retry might still be useful
    if (retryCount < MAX_RETRIES && !(error instanceof Error && error.message.startsWith('Failed to get models'))) {
      const delay = getExponentialBackoffDelay(retryCount);
      console.warn(`Get models network error. Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delay);
      return getModels(token, retryCount + 1);
    }
    throw error; // Rethrow after max retries or for non-retryable errors
  }
}

/**
 * Handles the chat completions request to the SophNet API.
 * @param {string} token - A valid anonymous token.
 * @param {object} requestBody - The original request body (OpenAI format).
 * @param {boolean} stream - Whether to request a streaming response.
 * @param {number} [retryCount=0] - The current retry attempt number.
 * @returns {Promise<Response>} The raw Response object from the SophNet API.
 * @throws {Error} If the request fails after maximum retries.
 */
async function handleChatCompletions(token, requestBody, env, stream, retryCount = 0) {
  const modelId = requestBody.model || '';
  const webSearchEnable = modelId.includes("-Search");
  const fullContextEnable = modelId.includes("-Full-Context");

  let actualModelId = modelId;
  if (webSearchEnable) actualModelId = actualModelId.replace("-Search", "");
  if (fullContextEnable) actualModelId = actualModelId.replace("-Full-Context", "");

  let processedMessages = requestBody.messages;
  if (fullContextEnable) {
    processedMessages = processFullContext(requestBody.messages);
  }

  const sophNetBody = {
    temperature: requestBody.temperature ?? 0.7,
    top_p: requestBody.top_p ?? 0.9,
    frequency_penalty: requestBody.frequency_penalty ?? 0,
    presence_penalty: requestBody.presence_penalty ?? 0,
    max_tokens: requestBody.max_tokens ?? 2048,
    webSearchEnable: webSearchEnable,
    stop: requestBody.stop ?? [],
    stream: stream, // Send boolean directly if API supports it, else use .toString()
    model_id: actualModelId,
    messages: processedMessages,
  };

  try {
    const response = await nativeFetch(
      `${SOPHNET_BASE_URL}/open-apis/projects/${PROJECT_UUID}/chat/completions`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer anon-${token}`,
          "Accept": stream ? "text/event-stream" : "application/json",
          "User-Agent": getRandomUserAgent(),
        },
        body: JSON.stringify(sophNetBody),
      }
    );

    // If token is invalid/expired (401/403), refresh token and retry
    if ((response.status === 401 || response.status === 403 || response.status === 422) && retryCount < MAX_RETRIES) {
      console.log(`Chat completion token expired or invalid (${response.status}), refreshing and retrying (${retryCount + 1}/${MAX_RETRIES})...`);
      const newToken = await getAnonymousToken(env);
      const delay = getExponentialBackoffDelay(retryCount);
      await sleep(delay);
      return await handleChatCompletions(newToken, requestBody, env, stream, retryCount + 1);
    }

    // Retry on 429 or 5xx errors
    if ((response.status === 429 || response.status >= 500) && retryCount < MAX_RETRIES) {
      const delay = getExponentialBackoffDelay(retryCount);
      console.warn(`Chat completion failed with status ${response.status}. Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delay);
      return handleChatCompletions(token, requestBody, stream, env, retryCount + 1);
    }

    if (!response.ok && response.status !== 401 && response.status !== 403 && response.status !== 429 && response.status < 500) {
      // Handle other client-side errors (e.g., 400 Bad Request) without retrying indefinitely
      const errorText = await response.text();
      console.error(`Chat completion failed: ${response.status} - ${errorText}`, sophNetBody);
      // Return the error response directly to the client
      return new Response(JSON.stringify({
        error: { message: `Upstream API error: ${response.status} - ${errorText}`, type: "upstream_error", code: response.status }
      }), {
        status: response.status, // Forward the original error status
        headers: { 'Content-Type': 'application/json', "Access-Control-Allow-Origin": "*" }
      });
    } else if (!response.ok) {
      // For errors we are retrying (401, 403, 429, 5xx) and reached max retries
      const errorText = await response.text();
      console.error(`Chat completion failed after retries: ${response.status} - ${errorText}`);
      throw new Error(`Chat completion failed: ${response.status}`);
    }


    // Optional: Background token refresh after successful request
    // getAnonymousToken().catch(err => console.error("Background token refresh failed:", err));

    return response; // Return the raw response on success or for retryable errors handled above

  } catch (error) {
    console.error("Error during chat completion fetch:", error);
    // Retry on network errors
    if (retryCount < MAX_RETRIES) {
      const delay = getExponentialBackoffDelay(retryCount);
      console.warn(`Chat completion network error. Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delay);
      return handleChatCompletions(token, requestBody, env, stream, retryCount + 1);
    }
    throw error; // Rethrow after max retries
  }
}

// ====================================================================================
// Data Transformation Functions (SophNet -> OpenAI Format)
// ====================================================================================

/**
 * Transforms SophNet models list to OpenAI compatible format.
 * @param {Array<object>} models - Array of SophNet model objects.
 * @returns {object} OpenAI formatted model list.
 */
function transformModelsToOpenAIFormat(models) {
  const transformedModels = [];
  const now = Math.floor(Date.now() / 1000); // Use Unix timestamp (seconds)

  for (const model of models) {
    const baseModelId = model.modelFamily || `sophnet-model-${model.id}`; // Fallback ID

    // Common permission object
    const permission = [{
      id: `modelperm-${model.id}-${Date.now()}`, // Ensure unique ID
      object: "model_permission",
      created: now,
      allow_create_engine: false,
      allow_sampling: true,
      allow_logprobs: false, // Typically false unless supported
      allow_search_indices: false, // Default, override below
      allow_view: true,
      allow_fine_tuning: false, // Typically false for base models via API
      organization: "*",
      group: null,
      is_blocking: false,
    }];

    // Helper to create model entries
    const createModelEntry = (idSuffix, allowSearch) => ({
      id: `${baseModelId}${idSuffix}`,
      object: "model",
      created: now,
      owned_by: "sophnet", // Or appropriate owner string
      permission: JSON.parse(JSON.stringify(permission)).map(p => { // Deep copy permission
        p.id = `modelperm-${model.id}${idSuffix}-${Date.now()}`; // Unique perm id
        p.allow_search_indices = allowSearch;
        return p;
      }),
      root: baseModelId,
      parent: null,
    });

    // Add variations: Standard, Search, Full-Context, Full-Context+Search
    transformedModels.push(createModelEntry("", false));
    transformedModels.push(createModelEntry("-Search", true));
    transformedModels.push(createModelEntry("-Full-Context", false));
    transformedModels.push(createModelEntry("-Full-Context-Search", true));
  }

  return {
    object: "list",
    data: transformedModels,
  };
}

/**
 * Processes messages for "Full-Context" mode by summarizing older messages.
 * @param {Array<object>} messages - Array of message objects ({ role: string, content: string }).
 * @returns {Array<object>} Processed array of message objects.
 */
function processFullContext(messages) {
  if (!Array.isArray(messages)) return []; // Handle invalid input

  const messagesCopy = [...messages];
  const systemMessages = messagesCopy.filter(msg => msg.role === "system");
  const nonSystemMessages = messagesCopy.filter(msg => msg.role !== "system");

  // Keep last 3 user/assistant pairs (max 6 messages)
  const historyThreshold = 6;
  if (nonSystemMessages.length <= historyThreshold) {
    return messages; // No processing needed
  }

  const recentMessages = nonSystemMessages.slice(-historyThreshold);
  const historyMessages = nonSystemMessages.slice(0, -historyThreshold);

  // Create a summary message (consider potential length limits)
  // Simple JSON stringify might exceed token limits for very long histories.
  // A more sophisticated summarization might be needed in practice.
  let historyContent;
  try {
    historyContent = JSON.stringify(historyMessages);
  } catch (e) {
    console.error("Could not stringify history messages:", e);
    historyContent = "[Error summarizing history]";
  }

  const historySummary = {
    role: "user", // Or 'system' might be better depending on the model
    content: `Here is the summarized context of the earlier conversation:\n${historyContent}`
  };

  // Combine: System messages + History Summary + Recent Messages
  return [...systemMessages, historySummary, ...recentMessages];
}

/**
 * Generates the Markdown formatted references section.
 * @param {Array<object>} references - Array of reference objects ({ title: string, url: string }).
 * @returns {string} Formatted references string or empty string.
 */
function generateReferencesSection(references) {
  if (!references || references.length === 0) return "";

  let section = "## 参考资料\n"; // Using Markdown heading
  references.forEach((ref, index) => {
    // Ensure ref has title and url before adding
    if(ref && ref.title && ref.url) {
      section += `${index + 1}. [${ref.title}](${ref.url})\n`;
    }
  });

  return section ? section + "\n" : ""; // Add trailing newline if section exists
}

/**
 * Transforms the SophNet SSE stream chunks into OpenAI compatible SSE chunks.
 * Handles references by collecting them and appending a formatted section at the end.
 * @param {ReadableStream<Uint8Array>} readableStream - The SophNet API response stream.
 * @param {string} modelName - The model name to include in the chunks.
 * @returns {AsyncGenerator<string>} An async generator yielding OpenAI formatted SSE chunks.
 */
async function* transformStreamResponse(readableStream, modelName = "sophnet-model") {
  const reader = readableStream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const references = [];
  let referencesEmitted = false;
  const uniqueRefUrls = new Set(); // Track unique URLs

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        // Process any remaining buffer content if needed
        if (buffer.trim()) {
          // This part might be tricky, usually SSE lines end with \n\n
          console.warn("Stream ended with unprocessed buffer:", buffer);
        }
        break; // Exit loop when stream is done
      }

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n"); // SSE events are separated by double newlines

      // Keep the last potentially incomplete line in the buffer
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.trim() === "") continue;

        // Check for the 'data:' prefix
        if (!line.startsWith("data:")) {
          // SophNet might send comments or other non-data lines
          // console.log("Skipping non-data line:", line);
          continue;
        }

        const data = line.substring(5).trim(); // Extract the JSON part

        if (data === "[DONE]") {
          // Append references section before the final [DONE] if needed
          if (references.length > 0 && !referencesEmitted) {
            const referencesSection = generateReferencesSection(references);
            if (referencesSection) {
              const refChunk = {
                id: `chatcmpl-${Date.now()}-refs`,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: modelName,
                choices: [{
                  index: 0,
                  delta: { content: `\n\n${referencesSection}` }, // Add extra newlines for spacing
                  finish_reason: null,
                }],
              };
              yield `data: ${JSON.stringify(refChunk)}\n\n`;
              referencesEmitted = true;
            }
          }
          yield "data: [DONE]\n\n";
          continue; // Move to next line/event
        }

        try {
          const sophNetEvent = JSON.parse(data);
          let contentDelta = "";
          let reasoningContentDelta = ""; // Capture reasoning content if available

          // Extract content and reasoning content
          if (sophNetEvent.choices && sophNetEvent.choices[0] && sophNetEvent.choices[0].delta) {
            contentDelta = sophNetEvent.choices[0].delta.content || "";
            reasoningContentDelta = sophNetEvent.choices[0].delta.reasoning_content || "";
          }

          // Check for and collect unique references from the chunk
          if (sophNetEvent.choices?.[0]?.refs && Array.isArray(sophNetEvent.choices[0].refs)) {
            for (const ref of sophNetEvent.choices[0].refs) {
              if (ref && ref.url && !uniqueRefUrls.has(ref.url)) {
                references.push({
                  ...ref,
                  // Add index for superscript mapping later if needed, though usually appended at the end
                  refIndex: references.length + 1
                });
                uniqueRefUrls.add(ref.url);
              }
            }
          }

          // Create the OpenAI formatted chunk
          const openAIEvent = {
            id: sophNetEvent.id || `chatcmpl-${Date.now()}`,
            object: "chat.completion.chunk",
            created: sophNetEvent.created || Math.floor(Date.now() / 1000),
            model: sophNetEvent.model || modelName,
            choices: [{
              index: 0,
              delta: {
                // Include reasoning_content if present, otherwise just content
                ...(reasoningContentDelta && { reasoning_content: reasoningContentDelta }),
                content: contentDelta,
              },
              // Map finish reason, default to null if not present
              finish_reason: sophNetEvent.choices?.[0]?.finish_reason || null,
            }],
            // Include usage if provided in the chunk (less common for streaming)
            ...(sophNetEvent.usage && { usage: sophNetEvent.usage }),
          };

          // Only yield if there's content or it's the final chunk with a finish reason
          if (contentDelta || reasoningContentDelta || openAIEvent.choices[0].finish_reason) {
            yield `data: ${JSON.stringify(openAIEvent)}\n\n`;
          }

        } catch (e) {
          console.error("Error parsing SophNet SSE event:", e, "Data:", data);
          // Optionally yield an error chunk to the client
          // const errorChunk = { error: { message: "Error parsing upstream event", data: data } };
          // yield `data: ${JSON.stringify(errorChunk)}\n\n`;
        }
      }
    }
  } catch (error) {
    console.error("Error reading or transforming stream:", error);
    // Yield an error chunk if the stream fails unexpectedly
    const errorChunk = {
      id: `chatcmpl-${Date.now()}-error`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: modelName,
      choices: [{
        index: 0,
        delta: { content: `\n\n[Stream Error: ${error.message || 'Unknown stream error'}]` },
        finish_reason: 'error', // Indicate error finish
      }],
    };
    yield `data: ${JSON.stringify(errorChunk)}\n\n`;
    yield "data: [DONE]\n\n"; // Still signal done after error
  } finally {
    // Ensure the reader is released even if errors occur
    try {
      await reader.cancel(); // Attempt to cancel the reader
      // reader.releaseLock(); // releaseLock() is often called implicitly by cancel or closing the stream
    } catch (e) {
      console.error("Error cancelling stream reader:", e);
    }
  }
}


/**
 * Transforms a non-streaming SophNet response into OpenAI format.
 * Appends references to the content.
 * @param {Response} response - The raw SophNet API Response object.
 * @param {string} modelName - The requested model name.
 * @returns {Promise<object>} OpenAI formatted chat completion object.
 */
async function transformNonStreamResponse(response, modelName = "sophnet-model") {
  let sophNetResponse;
  try {
    sophNetResponse = await response.json();
  } catch (e) {
    console.error("Failed to parse non-stream JSON response:", e);
    // Try to get text for better debugging, then throw
    const text = await response.text().catch(() => "[Could not read response text]");
    console.error("Response text:", text);
    throw new Error(`Failed to parse upstream JSON response. Status: ${response.status}. Body: ${text}`);
  }


  // Extract base content and potential references
  let content = sophNetResponse?.choices?.[0]?.message?.content || "";
  const reasoningContent = sophNetResponse?.choices?.[0]?.message?.reasoning_content || ""; // Capture reasoning content
  const references = sophNetResponse?.choices?.[0]?.message?.refs || [];
  const uniqueRefs = [];
  const uniqueRefUrls = new Set();

  // Process and collect unique references
  if (Array.isArray(references)) {
    references.forEach(ref => {
      if(ref && ref.url && !uniqueRefUrls.has(ref.url)) {
        uniqueRefs.push(ref);
        uniqueRefUrls.add(ref.url);
      }
    });
  }

  // Append superscript markers and reference list if references exist
  if (uniqueRefs.length > 0) {
    uniqueRefs.forEach((ref, index) => {
      const refIndex = index + 1;
      const superscriptIndex = `⁽${convertToSuperscript(refIndex)}⁾`;
      // Append marker - consider adding space for clarity
      content += ` [${superscriptIndex}](${ref.url})`;
    });

    // Append the formatted reference section
    const referencesSection = generateReferencesSection(uniqueRefs);
    if (referencesSection) {
      content += "\n\n" + referencesSection; // Add spacing before the section
    }
  }


  // Construct the OpenAI format response
  return {
    id: sophNetResponse.id || `chatcmpl-${Date.now()}`,
    object: "chat.completion",
    created: sophNetResponse.created || Math.floor(Date.now() / 1000),
    model: sophNetResponse.model || modelName, // Use actual model if provided, else fallback
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          // Include reasoning_content if present
          ...(reasoningContent && { reasoning_content: reasoningContent }),
          content: content,
        },
        finish_reason: sophNetResponse.choices?.[0]?.finish_reason || "stop", // Provide default
      },
    ],
    usage: sophNetResponse.usage || { // Provide default usage structure
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

// ====================================================================================
// Main Request Handler
// ====================================================================================

/**
 * Handles incoming requests, routes them, and manages responses.
 * @param {Request} request - The incoming request object.
 * @returns {Promise<Response>} The response to send back to the client.
 */
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS Preflight Request Handler
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*", // Allow all origins
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization", // Allow necessary headers
        "Access-Control-Max-Age": "86400", // Cache preflight response for 1 day
      },
    });
  }

  // Common headers for actual responses
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
  };

  // --- Authentication/Token Handling ---
  // You might want to add your own authentication layer here if this worker
  // is not intended for public use. For now, it relies solely on the SophNet token.

  let token;
  try {
    token = await getValidToken(env);
    if (!token) {
      throw new Error("Failed to retrieve a valid SophNet token.");
    }
  } catch (error) {
    console.error("Fatal: Could not get SophNet token in handleRequest:", error);
    return new Response(
      JSON.stringify({ error: { message: "Failed to authenticate with the backend service.", type: "auth_error", details: error.message } }),
      {
        status: 503, // Service Unavailable (can't talk to backend)
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }

  // --- Routing ---
  try {
    // Route: Get Models
    if (path === "/v1/models" && request.method === "GET") {
      const sophNetModels = await getModels(token);
      const openAIModels = transformModelsToOpenAIFormat(sophNetModels);
      return new Response(JSON.stringify(openAIModels), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Route: Chat Completions
    else if (path === "/v1/chat/completions" && request.method === "POST") {
      let requestBody;
      try {
        requestBody = await request.json();
      } catch (e) {
        return new Response(JSON.stringify({ error: { message: "Invalid JSON in request body.", type: "invalid_request_error" } }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const stream = requestBody.stream === true;
      const requestedModel = requestBody.model || 'unknown-model'; // Get model for logging/use

      const sophNetResponse = await handleChatCompletions(token, requestBody, env, stream);

      // Check if handleChatCompletions returned an error Response directly
      if (sophNetResponse.status >= 400 && sophNetResponse.headers.get('content-type')?.includes('application/json')) {
        // Forward the error response from SophNet (or the one we created for it)
        const body = await sophNetResponse.text(); // Read body to avoid issues
        return new Response(body, {
          status: sophNetResponse.status,
          headers: { ...corsHeaders, ...Object.fromEntries(sophNetResponse.headers), 'Content-Type': 'application/json' } // Preserve upstream headers if possible
        });
      }
      // Ensure we have a body for streaming
      if (stream && !sophNetResponse.body) {
        throw new Error("Upstream response for stream request has no body.");
      }


      if (stream) {
        // Set up the transformed stream
        const { readable, writable } = new TransformStream();
        const encoder = new TextEncoder();

        // Start piping the transformed data in the background, don't await it here
        (async () => {
          const writer = writable.getWriter();
          try {
            for await (const chunk of transformStreamResponse(sophNetResponse.body, requestedModel)) {
              await writer.write(encoder.encode(chunk));
            }
            await writer.close();
          } catch (error) {
            console.error("Error during stream transformation/writing:", error);
            // Try to write an error chunk to the stream if possible
            try {
              const errorData = JSON.stringify({ error: { message: `Stream processing error: ${error.message}`, type: "stream_error" } });
              await writer.write(encoder.encode(`data: ${errorData}\n\n`));
              await writer.write(encoder.encode("data: [DONE]\n\n")); // Still signal done
              await writer.close();
            } catch (writeError) {
              console.error("Failed to write error chunk to stream:", writeError);
              // Abort the writer if writing the error fails
              await writer.abort(writeError);
            }
          }
        })(); // Immediately invoked async function

        // Return the readable part of the TransformStream
        return new Response(readable, {
          status: 200, // Assuming success if we got this far
          headers: {
            ...corsHeaders,
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
          },
        });

      } else {
        // Handle non-streaming response
        const transformedResponse = await transformNonStreamResponse(sophNetResponse, requestedModel);
        return new Response(JSON.stringify(transformedResponse), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // Route: Not Found
    else {
      return new Response(
        JSON.stringify({ error: { message: `Not Found: ${request.method} ${path}`, type: "invalid_request_error"} }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }
  } catch (error) {
    // General Catch-All Error Handler
    console.error("Unhandled error in handleRequest:", error);
    // Check if it's an error with a status code (like from failed fetch retries)
    const status = error.status || 500;
    return new Response(
      JSON.stringify({
        error: {
          message: error.message || "An internal server error occurred.",
          type: "api_error",
          code: error.code || null, // Include code if available
          // Optionally include stack trace in non-production environments
          // stack: (ENVIRONMENT === 'development' ? error.stack : undefined)
        }
      }),
      {
        status: status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
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
