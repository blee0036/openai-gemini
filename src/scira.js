// 定义常量
const API_URL = "https://mcp.scira.ai/api/chat";
const FIXED_USER_ID = "2jFMDM1A1R_XxOTxPjhwe";
const FIXED_CHAT_ID = "ZIWa36kd6MSqzw-ifXGzE";
const DEFAULT_MODEL = "gpt-4.1-mini";
// PORT 常量不再需要

// 可用模型列表 (结构与 Deno 版本一致)
const AVAILABLE_MODELS = [
  {
    id: "gpt-4.1-mini",
    created: Date.now(),
    object: "model",
  },
  {
    id: "grok-3-mini",
    created: Date.now(),
    object: "model",
  },
];

// CORS Headers
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};


// 格式化消息为Scira格式
function formatMessagesForScira(messages) {
  return messages.map(msg => ({
    role: msg.role,
    content: msg.content,
    parts: [{
      type: "text",
      text: msg.content
    }]
  }));
}

// 构建Scira请求负载
function buildSciraPayload(messages, model = DEFAULT_MODEL) {
  const formattedMessages = formatMessagesForScira(messages);
  return {
    id: FIXED_CHAT_ID,
    messages: formattedMessages,
    selectedModel: model,
    mcpServers: [],
    chatId: FIXED_CHAT_ID,
    userId: FIXED_USER_ID
  };
}

// 处理模型列表请求
async function handleModelsRequest() {
  const response = {
    object: "list",
    data: AVAILABLE_MODELS,
  };
  return new Response(JSON.stringify(response), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders // 添加 CORS 头
    },
  });
}

// 处理聊天补全请求
async function handleChatCompletionsRequest(req) {
  const requestData = await req.json();
  const { messages, model = DEFAULT_MODEL, stream = false } = requestData;

  const sciraPayload = buildSciraPayload(messages, model);
  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
      "Accept": "*/*",
      "Referer": `https://mcp.scira.ai/chat/${FIXED_CHAT_ID}`,
      "Origin": "https://mcp.scira.ai",
    },
    body: JSON.stringify(sciraPayload),
  });

  if (!response.ok) {
    // 如果上游 API 返回错误，尝试将错误信息传递给客户端
    console.error("Upstream API Error:", response.status, await response.text());
    return new Response(JSON.stringify({ error: `Upstream API error: ${response.status}` }), {
      status: response.status, // Use upstream status code
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }

  if (stream && response.body) { // 检查 response.body 是否存在
    return handleStreamResponse(response, model);
  } else if (response.body) { // 检查 response.body 是否存在
    return handleRegularResponse(response, model);
  } else {
    // 处理 response.body 为 null 的情况（虽然 fetch 正常情况下应该有 body）
    console.error("Upstream response body is null");
    return new Response(JSON.stringify({ error: "Upstream response body is null" }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }
}

// 处理流式响应
async function handleStreamResponse(response, model) {
  const reader = response.body.getReader(); // 在 JS 中不需要 !
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const id = `chatcmpl-${Date.now().toString(36)}${Math.random().toString(36).substring(2, 10)}`;
  const createdTime = Math.floor(Date.now() / 1000);
  const systemFingerprint = `fp_${Math.random().toString(36).substring(2, 12)}`;

  const stream = new ReadableStream({
    async start(controller) {
      // 发送流式头部
      const headerEvent = {
        id: id,
        object: "chat.completion.chunk",
        created: createdTime,
        model: model,
        system_fingerprint: systemFingerprint,
        choices: [{
          index: 0,
          delta: { role: "assistant" },
          logprobs: null,
          finish_reason: null
        }]
      };
      controller.enqueue(encoder.encode(`data: ${JSON.stringify(headerEvent)}\n\n`));

      try {
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          // 解码当前数据块并添加到缓冲区
          buffer += decoder.decode(value, { stream: true });

          // 处理完整的行
          const lines = buffer.split('\n');
          // 保留最后一个可能不完整的行
          buffer = lines.pop() || "";

          // 处理并立即发送每一行
          for (const line of lines) {
            if (!line.trim()) continue;

            let eventData = null;
            if (line.startsWith('g:')) {
              // 对于g开头的行，输出reasoning_content
              let content = line.slice(2).replace(/^"/, "").replace(/"$/, "");
              content = content.replace(/\\n/g, "\n");
              eventData = { delta: { reasoning_content: content } };
            } else if (line.startsWith('0:')) {
              // 对于0开头的行，输出content
              let content = line.slice(2).replace(/^"/, "").replace(/"$/, "");
              content = content.replace(/\\n/g, "\n");
              eventData = { delta: { content: content } };
            } else if (line.startsWith('e:')) {
              // 完成消息
              try {
                const finishData = JSON.parse(line.slice(2));
                eventData = {
                  delta: {},
                  finish_reason: finishData.finishReason || "stop"
                };
              } catch (error) {
                console.error("Error parsing finish data in stream:", error, "Line:", line);
                // 可以选择忽略错误或发送错误信号，这里选择忽略
              }
            }
            // 忽略 'd:' 等其他开头的行

            if (eventData) {
              const event = {
                id: id,
                object: "chat.completion.chunk",
                created: createdTime,
                model: model,
                system_fingerprint: systemFingerprint,
                choices: [{
                  index: 0,
                  delta: eventData.delta || {},
                  logprobs: null,
                  finish_reason: eventData.finish_reason || null
                }]
              };
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
            }
          }
        }

        // 处理缓冲区中剩余的内容（如果有的话） - 这段逻辑可能重复，上面的循环应该已经处理了所有完整的行
        // 并且 decoder.decode({ stream: true }) 最后的调用应该已经完成
        // 如果 buffer 还有内容，通常意味着是非正常结束或数据格式问题
        if (buffer.trim()) {
          console.warn("Remaining buffer content after stream end:", buffer);
          // 根据需要决定是否处理剩余的 buffer
        }

      } catch (error) {
        console.error("Stream error:", error);
        // 可以选择向流中发送错误信息，但这不符合 OpenAI SSE 格式
        // controller.error(error); // 这会终止流
      } finally {
        // 确保发送 "data: [DONE]" 标记流结束
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
        reader.releaseLock(); // 释放 reader 锁
      }
    }
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      ...corsHeaders // 添加 CORS 头
    },
  });
}

// 处理非流式响应
async function handleRegularResponse(response, model) {
  const text = await response.text();
  const lines = text.split('\n');

  let content = "";
  let reasoning_content = "";
  let usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
  let finish_reason = "stop"; // 默认值

  for (const line of lines) {
    if (!line.trim()) continue;

    if (line.startsWith('0:')) {
      // 常规内容 - 处理转义的换行符
      let lineContent = line.slice(2).replace(/^"/, "").replace(/"$/, "");
      lineContent = lineContent.replace(/\\n/g, "\n");
      content += lineContent;
    } else if (line.startsWith('g:')) {
      // 推理内容 - 处理转义的换行符
      let lineContent = line.slice(2).replace(/^"/, "").replace(/"$/, "");
      lineContent = lineContent.replace(/\\n/g, "\n");
      reasoning_content += lineContent;
    } else if (line.startsWith('e:')) {
      try {
        const finishData = JSON.parse(line.slice(2));
        if (finishData.finishReason) {
          finish_reason = finishData.finishReason;
        }
      } catch (error) {
        console.error("Error parsing finish data:", error, "Line:", line);
      }
    } else if (line.startsWith('d:')) {
      try {
        const finishData = JSON.parse(line.slice(2));
        if (finishData.usage) {
          usage.prompt_tokens = finishData.usage.promptTokens || 0;
          usage.completion_tokens = finishData.usage.completionTokens || 0;
          usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
        }
      } catch (error) {
        console.error("Error parsing usage data:", error, "Line:", line);
      }
    }
    // 忽略其他开头的行
  }

  const systemFingerprint = `fp_${Math.random().toString(36).substring(2, 12)}`;
  const id = `chatcmpl-${Date.now().toString(36)}${Math.random().toString(36).substring(2, 10)}`;

  const openAIResponse = {
    id: id,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model,
    system_fingerprint: systemFingerprint,
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: content
      },
      logprobs: null,
      finish_reason: finish_reason
    }],
    usage: usage
  };

  // 如果存在推理内容，添加到消息中
  if (reasoning_content.trim()) {
    // OpenAI 官方格式没有 reasoning_content，可以作为自定义字段添加，
    // 但标准客户端可能不识别。这里保留原逻辑。
    openAIResponse.choices[0].message.reasoning_content = reasoning_content;
  }

  return new Response(JSON.stringify(openAIResponse), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders // 添加 CORS 头
    },
  });
}


// Cloudflare Worker 入口
export default {
  async fetch(request, env, ctx) { // env 和 ctx 可用于访问环境变量和执行上下文
    const url = new URL(request.url);

    // 处理 OPTIONS 预检请求 (用于 CORS)
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders, status: 204 });
    }

    try {
      // 路由处理
      if (request.method === "GET" && url.pathname === "/v1/models") {
        return handleModelsRequest();
      }

      if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
        return handleChatCompletionsRequest(request);
      }

      // 未找到的路由
      return new Response(
        JSON.stringify({ error: "Not found" }), {
          status: 404,
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders // 错误响应也添加 CORS 头
          },
        }
      );
    } catch (error) {
      console.error("Error processing request:", error);
      // 避免将详细错误暴露给客户端
      const errorMessage = error instanceof Error ? error.message : "Internal server error";
      return new Response(
        JSON.stringify({ error: "Internal Server Error" }), // 通用错误信息
        // JSON.stringify({ error: errorMessage }), // 或者更详细（谨慎使用）
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders // 错误响应也添加 CORS 头
          },
        }
      );
    }
  }
};
