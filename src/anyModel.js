// Configuration
const ANYMODEL_API_URL = "https://app.anymodel.xyz/api/text";

// Built-in model information
// The 'created' timestamp will be set when the worker initializes.
const MODELS_DATA = {
  object: "list",
  data: [
    {
      id: "anthropic/claude-3-5-sonnet-20240620",
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "anthropic"
    },
    {
      id: "openai/gpt-4o-mini",
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "openai"
    },
    {
      id: "openai/gpt-4.1-mini",
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "openai"
    },
    {
      id: "openai/gpt-4.1-nano",
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "openai"
    },
  ]
};

// --- Utility Functions (adapted for Cloudflare Workers) ---

function generateId() {
  return `chatcmpl-${crypto.randomUUID().replace(/-/g, '')}`;
}

function getCurrentTimestamp() {
  return Math.floor(Date.now() / 1000);
}

// Custom Error for Authorization issues
class AuthError extends Error {
  constructor(message, status, authHeaders) {
    super(message);
    this.name = "AuthError";
    this.status = status;
    if (authHeaders) {
      this.authHeaders = authHeaders;
    }
  }
}

function extractAnymodelToken(authHeader) {
  if (!authHeader) {
    throw new AuthError("Authorization header required", 401, { "WWW-Authenticate": "Bearer" });
  }
  const token = authHeader.replace(/^Bearer\s+/i, "").trim(); // More robust regex
  if (!token) {
    throw new AuthError("Valid token required in Authorization header", 401);
  }

  let keyArr = token.split(",");
  let anymodel_token = keyArr[Math.floor(Math.random() * keyArr.length)]
  console.log("use : " + anymodel_token);
  return anymodel_token;
}

function isValidModel(modelId) {
  return MODELS_DATA.data.some(model => model.id === modelId);
}

function createSseStream(chunks) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      Promise.resolve().then(() => {
        controller.close();
      });
    }
  });
}

// CORS Headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Helper for JSON responses
function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      ...extraHeaders,
    }
  });
}

// Helper for SSE responses
function sseResponse(stream, extraHeaders = {}) {
  return new Response(stream, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      ...extraHeaders,
    }
  });
}


// --- Main Fetch Event Listener ---
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request).catch(err => {
    console.error("Unhandled error in handleRequest:", err);
    if (err instanceof AuthError) {
      return jsonResponse({ error: { message: err.message, type: "authentication_error" } }, err.status, err.authHeaders);
    }
    return jsonResponse({ error: { message: "Internal Server Error", type: "internal_error" } }, 500);
  }));
});

async function handleRequest(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  const url = new URL(request.url);
  const { pathname } = url;

  try {
    if ((pathname === "/v1/models" || pathname === "/models") && request.method === "GET") {
      return jsonResponse(MODELS_DATA);
    }

    if (pathname === "/health" && request.method === "GET") {
      return jsonResponse({
        status: "ok",
        model: MODELS_DATA.data[0]?.id || "anthropic/claude-3-5-sonnet-20240620",
        service: "anymodel-openai-adapter"
      });
    }

    if (pathname === "/v1/chat/completions" && request.method === "POST") {
      return await handleChatCompletions(request);
    }

    return jsonResponse({ error: { message: "Not Found", type: "invalid_request_error" } }, 404);

  } catch (error) {
    if (error instanceof AuthError) {
      return jsonResponse({ error: { message: error.message, type: "authentication_error" } }, error.status, error.authHeaders);
    }
    if (error instanceof SyntaxError) {
      return jsonResponse({ error: { message: "Invalid JSON payload", type: "invalid_request_error" } }, 400);
    }
    console.error("Error processing request:", error);
    const message = error instanceof Error ? error.message : "An unexpected error occurred.";
    return jsonResponse({ error: { message: message, type: "internal_server_error" } }, 500);
  }
}

// --- Chat Completions Handler ---
async function handleChatCompletions(request) {
  let requestBody;
  try {
    requestBody = await request.json();
  } catch (e) {
    return jsonResponse({ error: { message: "Invalid JSON body", type: "invalid_request_error", code: "invalid_json" }}, 400);
  }

  const anymodelToken = extractAnymodelToken(request.headers.get("authorization"));

  if (!isValidModel(requestBody.model)) {
    return jsonResponse({
      error: {
        message: `Model '${requestBody.model}' not found. Available model: ${MODELS_DATA.data[0]?.id || 'N/A'}`,
        type: "invalid_request_error",
        code: "model_not_found"
      }
    }, 404);
  }

  if (!requestBody.messages || requestBody.messages.length === 0) {
    return jsonResponse({
      error: {
        message: "No messages provided in the request.",
        type: "invalid_request_error",
        code: "no_messages"
      }
    }, 400);
  }

  let currentPromptContent = requestBody.messages[requestBody.messages.length - 1].content;
  let systemPrompt = null;

  const historyListForAnymodel = [];
  const processedMessagesForHistory = requestBody.messages.slice(0, -1);
  let i = 0;
  while (i < processedMessagesForHistory.length) {
    const msg1 = processedMessagesForHistory[i];
    if (msg1.role !== "user") {
      i += 1;
      let role = msg1.role.toUpperCase();
      systemPrompt = `<${role}_PROMPT>`;
      systemPrompt += "\n" +msg1.content;
      systemPrompt += `</${role}_PROMPT>` + "\n\n";
    }
    else {
      i += 1;
      if (i >= processedMessagesForHistory.length) {
        break
      }
      const msg2 = processedMessagesForHistory[i];
      if (msg1.role === "user" && msg2.role === "assistant") {
        historyListForAnymodel.push({
          prompt: msg1.content,
          response: msg2.content,
          functionCalls: [],
          functionResponses: []
        });
        i += 1;
      }
    }
  }

  if (systemPrompt != null) {
    if (historyListForAnymodel.length > 0) {
      historyListForAnymodel[0].prompt = systemPrompt + historyListForAnymodel[0].prompt;
    }
    else {
      currentPromptContent = systemPrompt + currentPromptContent;
    }
  }

  console.log("cur : " + currentPromptContent);

  const anymodelPayload = {
    prompt: currentPromptContent,
    image: null,
    pdf: null,
    options: {
      models: [requestBody.model],
      generatePromptSummary: false,
      ...(requestBody.temperature !== undefined && { temperature: requestBody.temperature }),
      ...(requestBody.max_tokens !== undefined && { max_tokens: requestBody.max_tokens }),
      ...(requestBody.top_p !== undefined && { top_p: requestBody.top_p }),
    },
    history: historyListForAnymodel.length > 0 ? { [requestBody.model]: historyListForAnymodel } : {},
  };

  const headersToAnymodel = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "authorization": anymodelToken,
    "origin": "https://app.anymodel.xyz",
    "referer": "https://app.anymodel.xyz/",
  };

  try {
    const anymodelResponse = await fetch(ANYMODEL_API_URL, {
      method: "POST",
      headers: headersToAnymodel,
      body: JSON.stringify(anymodelPayload),
    });

    if (!anymodelResponse.ok) {
      const errorText = await anymodelResponse.text();
      let errorMessage = errorText;
      try {
        const errorJson = JSON.parse(errorText);
        errorMessage = errorJson.message || errorJson.error?.message || errorText;
      } catch {
        // Use raw errorText
      }
      throw new Error(`Anymodel API Error (${anymodelResponse.status}): ${errorMessage}`);
    }

    const responseJson = await anymodelResponse.json();

    let fullContent = "";
    if (responseJson.responses && responseJson.responses.length > 0) {
      const firstResponseItem = responseJson.responses[0];
      if (typeof firstResponseItem === "object" && firstResponseItem !== null) {
        fullContent = firstResponseItem.content || "";
      } else {
        fullContent = String(firstResponseItem || "");
      }
    }

    console.log("response :" + fullContent)

    if (requestBody.stream) {
      const streamId = generateId();
      const createdTime = getCurrentTimestamp();
      const chunks = [];

      chunks.push(`data: ${JSON.stringify({
        id: streamId,
        object: "chat.completion.chunk",
        created: createdTime,
        model: requestBody.model,
        choices: [{
          delta: { role: "assistant" },
          index: 0,
          finish_reason: null
        }]
      })}\n\n`);

      if (fullContent) {
        chunks.push(`data: ${JSON.stringify({
          id: streamId,
          object: "chat.completion.chunk",
          created: createdTime,
          model: requestBody.model,
          choices: [{
            delta: { content: fullContent },
            index: 0,
            finish_reason: null
          }]
        })}\n\n`);
      }

      chunks.push(`data: ${JSON.stringify({
        id: streamId,
        object: "chat.completion.chunk",
        created: createdTime,
        model: requestBody.model,
        choices: [{
          delta: {},
          index: 0,
          finish_reason: "stop"
        }]
      })}\n\n`);

      chunks.push("data: [DONE]\n\n");

      const readableStream = createSseStream(chunks);
      return sseResponse(readableStream);

    } else {
      const chatResponse = {
        id: generateId(),
        object: "chat.completion",
        created: getCurrentTimestamp(),
        model: requestBody.model,
        choices: [{
          message: {
            role: "assistant",
            content: fullContent
          },
          index: 0,
          finish_reason: "stop"
        }],
      };
      return jsonResponse(chatResponse);
    }

  } catch (error) {
    console.error("Error calling Anymodel API or processing its response:", error);
    const errorDetail = error instanceof Error ? error.message : "Unknown error during Anymodel API interaction";

    if (requestBody && requestBody.stream) { // Check if requestBody is defined
      const streamId = generateId();
      const createdTime = getCurrentTimestamp();
      const errorChunks = [
        `data: ${JSON.stringify({
          id: streamId,
          object: "chat.completion.chunk",
          created: createdTime,
          model: requestBody.model || MODELS_DATA.data[0].id,
          choices: [{
            delta: {content: `Error: ${errorDetail}`},
            index: 0,
            finish_reason: "error"
          }]
        })}\n\n`,
        `data: ${JSON.stringify({
          id: streamId,
          object: "chat.completion.chunk",
          created: createdTime,
          model: requestBody.model || MODELS_DATA.data[0].id,
          choices: [{
            delta: {},
            index: 0,
            finish_reason: "error"
          }]
        })}\n\n`,
        "data: [DONE]\n\n"
      ];
      return sseResponse(createSseStream(errorChunks), { 'X-Error-Type': 'anymodel_api_error' });
    } else {
      return jsonResponse({ error: { message: errorDetail, type: "api_error", code: "anymodel_api_failed" } }, 502);
    }
  }
}
