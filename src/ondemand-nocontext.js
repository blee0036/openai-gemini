// 常量
const ONDEMAND_API_BASE_URL = "https://api.on-demand.io"; // API基础URL，根据要求硬编码
// 常量
const MODEL_TO_ENDPOINT_MAP = {
  'gpt-4o': 'predefined-openai-gpt4o',
  'gpt-4o-mini': 'predefined-openai-gpt4o-mini',
  'deepseek-v3': 'predefined-deepseek-v3',
  'gpt-o3-mini': 'predefined-openai-gpto3-mini',
  'claude-3.7-sonnet': 'predefined-claude-3.7-sonnet',
  'gemini-2.0-flash': 'predefined-gemini-2.0-flash',
  'gpt-4.1': 'predefined-openai-gpt4.1',
  'gpt-4.1-mini': 'predefined-openai-gpt4.1-mini',
  'gpt-4.1-nano': 'predefined-openai-gpt4.1-nano',
  default: 'predefined-openai-gpt4o',
};
const __query_prefix = ''; // OnDemand查询的固定中文前缀
const KV_SESSION_TTL_SECONDS = 3600; // KV中会话ID的过期时间（1小时，单位：秒）

// 辅助函数：获取环境变量（目前主要用于R2相关配置）
function getEnv(env, key, defaultValue) {
  return env[key] || defaultValue;
}

// 辅助函数：计算SHA-256哈希值
async function sha256(message) {
  const msgUint8 = new TextEncoder().encode(message); // 将消息编码为UTF-8的Uint8Array
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8); // 计算哈希
  const hashArray = Array.from(new Uint8Array(hashBuffer)); // 转换为字节数组
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join(''); // 转换为十六进制字符串
  return hashHex;
}

/**
 * 将Base64编码的图像数据上传到R2。
 * 需要 R2_BUCKET 绑定和 R2_PUBLIC_URL_PREFIX 环境变量。
 */
async function uploadBase64ToR2(base64Data, env) {
  if (!env.R2_BUCKET) {
    console.error('R2_BUCKET 绑定未配置，无法上传图像。');
    throw new Error('R2_BUCKET 绑定未配置。');
  }
  const R2_PUBLIC_URL_PREFIX = getEnv(env, 'R2_PUBLIC_URL_PREFIX');
  if (!R2_PUBLIC_URL_PREFIX) {
    console.error('R2_PUBLIC_URL_PREFIX 环境变量未配置，无法上传图像。');
    throw new Error('R2_PUBLIC_URL_PREFIX 环境变量未配置。');
  }

  try {
    // 从Base64数据中提取MIME类型和内容
    const parts = base64Data.match(/^data:(image\/\w+);base64,(.*)$/);
    if (!parts || parts.length !== 3) {
      throw new Error('无效的Base64图像数据格式。');
    }
    const mimeType = parts[1];
    const base64Content = parts[2];

    // 将Base64内容解码为二进制数据
    const imageBuffer = Uint8Array.from(atob(base64Content), (c) => c.charCodeAt(0));
    // 生成唯一文件名
    const fileName = `image-${crypto.randomUUID()}.${mimeType.split('/')[1] || 'png'}`;

    // 上传到R2
    await env.R2_BUCKET.put(fileName, imageBuffer, {
      httpMetadata: { contentType: mimeType },
    });

    // 构建并返回R2公共链接
    const r2Link = `${R2_PUBLIC_URL_PREFIX.replace(/\/$/, '')}/${fileName}`;
    console.log(`[+] 图像成功上传到R2: ${r2Link}`);
    return r2Link;
  } catch (error) {
    console.error(`上传Base64到R2时出错: ${error.message}`, error.stack);
    throw error; // 重新抛出错误，由调用者处理
  }
}

/**
 * 获取或创建OnDemand会话ID，使用Cloudflare KV进行缓存。
 * onDemandApiKey 从请求头中传入。
 */
async function getOndemandSessionId(userId, onDemandApiKey, env) {
  // // 检查KV绑定是否存在
  // if (!env.OD_SESSION) {
  //   // 根据用户要求，KV绑定名称为 OD_SESSION
  //   console.warn('OD_SESSION KV绑定未找到。会话缓存将被跳过。');
  // }
  //
  // const cacheKey = `session:${onDemandApiKey}:${userId}`; // KV中缓存的键名
  // let sessionId = null;
  // // 如果KV绑定存在，则尝试从KV获取缓存的会话ID
  // if (env.OD_SESSION) {
  //   try {
  //     sessionId = await env.OD_SESSION.get(cacheKey);
  //     if (sessionId) {
  //       console.log(`从KV中获取到用户 ${userId} 的缓存会话ID。`);
  //       return {
  //         sessionId,
  //         isNewSession: false
  //       };
  //     }
  //   } catch (kvError) {
  //     console.error(`获取会话ID时KV出错: ${kvError.message}。将创建新会话。`);
  //   }
  // }

  // 如果未从缓存获取到，则创建新会话
  const createSessionUrl = `${ONDEMAND_API_BASE_URL}/chat/v1/sessions`;
  const payload = { externalUserId: userId, pluginIds: [] };
  const headers = {
    'Content-Type': 'application/json',
    apikey: onDemandApiKey, // 使用从请求头传入的API密钥
  };

  try {
    const response = await fetch(createSessionUrl, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`OnDemand会话创建失败: ${response.status} ${errorBody}`);
      throw new Error(`OnDemand会话创建失败: ${response.status} ${errorBody}`);
    }

    const data = await response.json();
    const newSessionId = data?.data?.id;
    if (!newSessionId) {
      console.error('在OnDemand响应中未找到新的会话ID:', data);
      throw new Error('在OnDemand响应中未找到新的会话ID。');
    }

    // // 如果KV绑定存在，则将新会话ID存入KV并设置过期时间
    // if (env.OD_SESSION) {
    //   try {
    //     await env.OD_SESSION.put(cacheKey, newSessionId, { expirationTtl: KV_SESSION_TTL_SECONDS });
    //     console.log(`为用户 ${userId} 创建并缓存了新的会话ID到KV: ${newSessionId}`);
    //   } catch (kvError) {
    //     console.error(`存储会话ID时KV出错: ${kvError.message}`);
    //   }
    // } else {
    //   console.log(`为用户 ${userId} 创建了新会话: ${newSessionId} (KV缓存已跳过)`);
    // }
    return {
      sessionId: newSessionId,
      isNewSession: true
    };
  } catch (error) {
    console.error(`在getOndemandSessionId中出错: ${error.message}`, error.stack);
    throw error;
  }
}

/**
 * 上传媒体文件到OnDemand服务。
 * onDemandApiKey 从请求头中传入。
 */
async function mediaUpload(sessionId, fileUrl, onDemandApiKey, env) {
  const mediaUploadUrl = `${ONDEMAND_API_BASE_URL}/media/v1/public/file`;
  const mediaUploadHeaders = {
    apikey: onDemandApiKey, // 使用从请求头传入的API密钥
    'Content-Type': 'application/json',
  };
  const mediaUploadPayload = {
    sessionId: sessionId,
    url: fileUrl,
    plugins: ['plugin-1713958591'], // 根据Python代码中的固定插件ID
    responseMode: 'sync',
  };

  console.log(`媒体上传负载: ${JSON.stringify(mediaUploadPayload, null, 2)}`);

  try {
    const response = await fetch(mediaUploadUrl, {
      method: 'POST',
      headers: mediaUploadHeaders,
      body: JSON.stringify(mediaUploadPayload),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`媒体上传失败: ${response.status} ${errorBody}`);
      throw new Error(`媒体上传失败: ${response.status} ${errorBody}`);
    }
    const mediaUploadData = await response.json();
    console.log(`媒体上传响应: ${JSON.stringify(mediaUploadData, null, 2)}`);

    if (mediaUploadData?.data?.actionStatus !== 'completed') {
      console.error('媒体上传未成功完成:', mediaUploadData);
      return '错误：媒体上传失败或未完成。';
    }
    return mediaUploadData?.data?.extractedText || ''; // 返回提取的文本，如果不存在则返回空字符串
  } catch (error) {
    console.error(`在mediaUpload中出错: ${error.message}`, error.stack);
    return `错误：媒体上传异常 - ${error.message}`;
  }
}

/**
 * 为OnDemand API请求创建负载。
 * onDemandApiKey 参数在此函数中目前不直接使用，但为了媒体上传等下游函数调用而传递。
 */
async function createOndemandPayload(request, sessionId, isNewSession, onDemandApiKey, env) {
  let toolPromptParts = []; // 用于构建工具使用提示的数组
  if (request.tools) {
    // 如果请求中包含工具定义
    try {
      const toolDescriptions = JSON.stringify(request.tools); // 将工具定义序列化为JSON字符串
      toolPromptParts.push(`You have access to the following tools:
\`\`\`json
${toolDescriptions}
\`\`\`
If you need to call one or more tools, respond *only* with a JSON object matching the following schema. Do not include *any* other text before or after the JSON object:
\`\`\`json
{
  "tool_calls": [
    {
      "id": "call_...",
      "type": "function",
      "function": {
        "name": "tool_name",
        "arguments": "{\\"arg1\\": \\"value1\\", \\"arg2\\": value2}"
      }
    }
  ]
}
\`\`\`
The 'arguments' field must be a JSON string.`);
    } catch (e) {
      console.error(`错误：无法将工具序列化为JSON: ${e}`);
      toolPromptParts.push(`You have access to the following tools:
\`\`\`json
[{"error": "Invalid tool format provided."}]
\`\`\`
...`); // 发生错误时的回退提示
    }
  }

  // 处理工具选择逻辑
  if (request.tool_choice) {
    if (typeof request.tool_choice === 'string') {
      if (request.tool_choice === 'none') toolPromptParts.push('You MUST NOT call any tools.');
      else if (request.tool_choice === 'auto') toolPromptParts.push('You may choose to call a tool if appropriate.');
      else if (request.tool_choice === 'required') toolPromptParts.push('You MUST call one of the available tools.');
    } else if (typeof request.tool_choice === 'object' && request.tool_choice.type === 'function') {
      const funcName = request.tool_choice.function?.name;
      if (funcName) toolPromptParts.push(`You MUST call the tool named '${funcName}'.`);
    }
  }
  const toolPrompt = toolPromptParts.join('\n\n'); // 将所有工具提示部分合并

  let systemPromptContent = null; // 系统提示内容
  const userMessagesContents = []; // 用户消息内容列表
  let mediaExtractedText = null; // 从图像中提取的文本

  // 遍历消息，提取系统提示和用户消息内容
  for (const msg of request.messages) {
    let contentStr = null;
    if (msg.content !== null && msg.content !== undefined) {
      if (typeof msg.content === 'string') {
        contentStr = msg.content;
      } else if (Array.isArray(msg.content)) {
        // 处理复杂内容（如文本和图像混合）
        for (const item of msg.content) {
          if (item.type === 'text') {
            contentStr = item.text; // 提取文本部分
          }
        }
      } else {
        // 其他类型的内容，尝试序列化为JSON
        try {
          contentStr = JSON.stringify(msg.content);
        } catch (e) {
          contentStr = String(msg.content); // 序列化失败则转为字符串
        }
      }
    }
    if (msg.role === 'system' && contentStr) {
      systemPromptContent = contentStr;
    } else if (msg.role === 'user' && contentStr !== null) {
      userMessagesContents.push(contentStr);
    }
  }

  // 构建最终的查询字符串
  const finalQueryParts = [];
  if (toolPrompt) {
    // 如果有工具提示，则添加
    finalQueryParts.push('TOOLS\n' + toolPrompt);
  }
  // 如果是没切换key或者正常session
  if (userMessagesContents.length > 1 && !isNewSession) {
    // 添加最后一条用户消息
    finalQueryParts.push(`User:\n${userMessagesContents[userMessagesContents.length - 1]}`);
  }
  // 如果是切换了key，上下文是新建的，把所有对话都发送过去
  // 按照顺序添加所有助手"role": "assistant"和用户消息："role": "user"
  if (isNewSession) {
    for (const msg of request.messages) {
      if (msg.role === 'assistant') {
        finalQueryParts.push(`Assistant:\n${msg.content}`);
      } else if (msg.role === 'user') {
        finalQueryParts.push(`User:\n${msg.content}`);
      }
    }
  }


  let finalQuery = finalQueryParts.join('\n\n');
  finalQuery += `\n\n${__query_prefix}`; // 添加固定的中文查询前缀
  if (mediaExtractedText) {
    // 如果从图像中提取了文本，则添加
    finalQuery += `\n\n image showing: ${mediaExtractedText}`;
  }
  console.log(`调试：构造的OnDemand查询:\n-------\n${finalQuery}\n-------`);

  // 获取OnDemand端点ID
  const endpointId = MODEL_TO_ENDPOINT_MAP[request.model] || MODEL_TO_ENDPOINT_MAP['default'];
  // 构建OnDemand API的请求负载
  const payload = {
    endpointId: endpointId,
    query: finalQuery,
    responseMode: request.stream ? 'stream' : 'sync', // 根据请求设置同步或流式响应
    pluginIds: [], // 根据Python代码，固定为空数组
  };

  // 模型配置
  const modelConfigs = {
    fulfillmentPrompt: (systemPromptContent || ''),
    stopTokens: [],
    maxTokens: 0, // 默认值，可能表示不设置或使用模型默认值
    temperature: 1,
    presencePenalty: 0,
    frequencyPenalty: 0,
    topP: 1,
  };
  // 将OpenAI参数映射到OnDemand模型配置
  if (request.temperature !== null && request.temperature !== undefined) modelConfigs.temperature = request.temperature;
  if (request.top_p !== null && request.top_p !== undefined) modelConfigs.topP = request.top_p;
  if (request.presence_penalty !== null && request.presence_penalty !== undefined) modelConfigs.presencePenalty = request.presence_penalty;
  if (request.frequency_penalty !== null && request.frequency_penalty !== undefined)
    modelConfigs.frequencyPenalty = request.frequency_penalty;
  if (request.max_tokens !== null && request.max_tokens !== undefined) modelConfigs.maxTokens = request.max_tokens;

  if (request.stop) {
    // 处理停止序列
    const stopSequences = [];
    if (typeof request.stop === 'string') stopSequences.push(request.stop);
    else if (Array.isArray(request.stop)) stopSequences.push(...request.stop.filter((s) => typeof s === 'string'));
    if (stopSequences.length > 0) modelConfigs.stopSequences = stopSequences;
  }

  // 根据模型ID设置推理模式
  const modelIdLower = request.model.toLowerCase();
  const mediumReasoningTriggers = ['claude-3.7', 'o1', 'o3', 'o4', 'r1']; // Python代码中的触发器
  if (mediumReasoningTriggers.some((trigger) => modelIdLower.includes(trigger))) {
    payload.reasoningMode = 'medium';
  }
  if (modelIdLower.includes('4.1')) {
    // 特定覆盖
    payload.reasoningMode = 'omni';
  }

  if (Object.keys(modelConfigs).length > 0) {
    payload.modelConfigs = modelConfigs;
  }
  return payload;
}

/**
 * 流式处理OnDemand API的响应。
 * onDemandRequestHeaders 包含从原始请求传入的API密钥。
 */
async function* streamOndemandResponse(sessionId, payload, onDemandRequestHeaders, originalModel, env) {
  const queryUrl = `${ONDEMAND_API_BASE_URL}/chat/v1/sessions/${sessionId}/query`;
  console.log(`[调试] 发送查询到OnDemand API: ${queryUrl}`);
  console.log(`OnDemand负载: ${JSON.stringify(payload, null, 2)}`);
  console.log(`OnDemand请求头: ${JSON.stringify(onDemandRequestHeaders, null, 2)}`);

  let firstSseSent = false; // 是否已发送第一个SSE事件（角色信息）
  let jsonAssemblyBuffer = ''; // 用于累积可能构成JSON工具调用的内容块 (重命名自 contentBuffer)
  let toolCallDetectedAndSent = false; // 是否已检测到并发送了工具调用
  const streamId = `chatcmpl-${crypto.randomUUID()}`; // 为流式响应生成唯一ID

  let lineBuffer = ''; // 用于从 reader.read() 的数据块中缓冲并提取完整的行

  try {
    const response = await fetch(queryUrl, {
      method: 'POST',
      headers: onDemandRequestHeaders, // 使用包含API密钥的请求头
      body: JSON.stringify(payload),
    });

    if (!response.ok || !response.body) {
      // 检查响应是否成功且包含响应体
      const errorBody = await response.text();
      console.error(`OnDemand流式错误 ${response.status}: ${errorBody}`);
      // 构造并发送错误信息块
      const errorChunk = {
        id: streamId,
        object: 'chat.completion.chunk',
        created: Math.floor(Date.now() / 1000),
        model: originalModel,
        choices: [
          { index: 0, delta: { role: 'assistant', content: `OnDemand流式错误 ${response.status}: ${errorBody}` }, finish_reason: 'stop' },
        ],
      };
      yield `data: ${JSON.stringify(errorChunk)}\n\n`;
      return;
    }

    // 使用TextDecoderStream处理响应体
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();

    // 循环读取流数据
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        // 如果流结束
        if (lineBuffer.trim().length > 0) {
          console.warn('[调试] 流结束，但行缓冲区中仍有未处理的片段:', lineBuffer);
        }
        console.log('[调试] 流读取器已完成。');
        break;
      }

      lineBuffer += value; // 将读取到的数据块追加到行缓冲区
      let newlineIndex;

      // 循环处理行缓冲区中的完整行
      while ((newlineIndex = lineBuffer.indexOf('\n')) >= 0) {
        const currentLine = lineBuffer.substring(0, newlineIndex); // 提取一行
        lineBuffer = lineBuffer.substring(newlineIndex + 1); // 从行缓冲区移除已提取的行和换行符

        const trimmedLine = currentLine.trim(); // 去除行首尾空格

        if (!trimmedLine || trimmedLine.startsWith('event:')) {
          // 跳过空行和事件行
          continue;
        }

        if (trimmedLine.startsWith('data:')) {
          // 处理数据行
          const dataContent = trimmedLine.substring('data:'.length).trimStart(); // 提取数据内容，只去除前导空格

          if (dataContent === '[DONE]') {
            // OnDemand流结束标记
            console.log('[调试] 收到来自OnDemand的[DONE]标记。');
            toolCallDetectedAndSent = true; // 标记为已处理，防止 finally 块发送多余的 stop
            await reader.cancel(); // 取消读取器
            return; // 退出生成器函数
          }

          if (dataContent.startsWith('[ERROR]:')) {
            // OnDemand流内错误标记
            const errorMessage = dataContent.substring('[ERROR]:'.length).trim();
            console.log(`[调试] OnDemand流错误数据: ${errorMessage}`);
            const errorChunk = {
              // 构造错误块
              id: streamId,
              object: 'chat.completion.chunk',
              created: Math.floor(Date.now() / 1000),
              model: originalModel,
              choices: [{ index: 0, delta: { role: 'assistant', content: `OnDemand流错误: ${errorMessage}` }, finish_reason: 'stop' }],
            };
            yield `data: ${JSON.stringify(errorChunk)}\n\n`;
            continue;
          }

          let contentChunkTextToProcess = null; // 当前SSE事件要处理的文本内容

          try {
            // 尝试将dataContent解析为JSON，以提取 "answer" 或 "reasoning"
            const ondemandData = JSON.parse(dataContent);
            contentChunkTextToProcess = ondemandData.answer || ondemandData.reasoning;
          } catch (e) {
            // 如果JSON.parse失败，假定dataContent本身就是文本内容 (除非它是已知标记)
            // 这处理了您日志中 "Unterminated string in JSON" 的情况
            if (dataContent !== '[DONE]' && !dataContent.startsWith('[ERROR]:')) {
              console.warn(`无法将dataContent解析为JSON: "${dataContent}"。将其视为原始文本块。错误: ${e.message}`);
              contentChunkTextToProcess = dataContent;
            } else {
              // 如果是[DONE]或[ERROR]等已在此处不应出现的标记，则记录错误并跳过
              console.error('[调试] 意外：在JSON解析回退逻辑中遇到标记:', dataContent);
              continue;
            }
          }

          // 如果成功提取或回退获得了要处理的文本内容
          if (contentChunkTextToProcess !== null && contentChunkTextToProcess !== undefined) {
            jsonAssemblyBuffer += contentChunkTextToProcess; // 累积到用于工具调用检测的缓冲区
            const bufferStripped = jsonAssemblyBuffer.trim();
            let possibleToolCall = false;
            let parsedToolCalls = null;

            // 检查累积的缓冲区是否构成一个完整的JSON工具调用
            if (bufferStripped.startsWith('{') && bufferStripped.endsWith('}')) {
              try {
                const parsedJson = JSON.parse(bufferStripped);
                if (parsedJson && typeof parsedJson === 'object' && Array.isArray(parsedJson.tool_calls)) {
                  const isValidFormat = parsedJson.tool_calls.every(
                    (call) => call && typeof call === 'object' && call.id && call.type && call.function,
                  );
                  if (isValidFormat) {
                    parsedToolCalls = parsedJson.tool_calls;
                    possibleToolCall = true;
                  }
                }
              } catch (e) {
                /* 解析工具调用JSON失败则忽略 */
              }
            }

            if (possibleToolCall && parsedToolCalls) {
              // 如果是工具调用
              if (!firstSseSent) {
                const roleChunk = {
                  id: streamId,
                  object: 'chat.completion.chunk',
                  created: Math.floor(Date.now() / 1000),
                  model: originalModel,
                  choices: [{ index: 0, delta: { role: 'assistant' } }],
                };
                yield `data: ${JSON.stringify(roleChunk)}\n\n`;
                firstSseSent = true;
              }
              const toolCallChunk = {
                id: streamId,
                object: 'chat.completion.chunk',
                created: Math.floor(Date.now() / 1000),
                model: originalModel,
                choices: [{ index: 0, delta: { tool_calls: parsedToolCalls } }],
              };
              yield `data: ${JSON.stringify(toolCallChunk)}\n\n`;
              const finishChunk = {
                id: streamId,
                object: 'chat.completion.chunk',
                created: Math.floor(Date.now() / 1000),
                model: originalModel,
                choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }],
              };
              yield `data: ${JSON.stringify(finishChunk)}\n\n`;
              toolCallDetectedAndSent = true;
              console.log('[调试] 工具调用已检测并发送，中断流。');
              await reader.cancel();
              return; // 退出生成器
            } else if (bufferStripped.startsWith('{') && !bufferStripped.endsWith('}')) {
              // 内容可能是工具调用JSON的开头但未结束，继续缓冲jsonAssemblyBuffer
              // 此时不发送当前的 contentChunkTextToProcess 作为delta，等待完整JSON
              console.log('[调试] jsonAssemblyBuffer看起来像JSON的开始，继续缓冲（工具调用检测）。');
            } else {
              // 不是工具调用，或工具调用JSON解析失败，或不是一个持续的JSON对象
              // 发送当前的文本块作为内容增量
              if (!firstSseSent) {
                const roleChunk = {
                  id: streamId,
                  object: 'chat.completion.chunk',
                  created: Math.floor(Date.now() / 1000),
                  model: originalModel,
                  choices: [{ index: 0, delta: { role: 'assistant' } }],
                };
                yield `data: ${JSON.stringify(roleChunk)}\n\n`;
                firstSseSent = true;
              }
              const contentDeltaPayload = {
                id: streamId,
                object: 'chat.completion.chunk',
                created: Math.floor(Date.now() / 1000),
                model: originalModel,
                choices: [{ index: 0, delta: { content: contentChunkTextToProcess } }],
              };
              yield `data: ${JSON.stringify(contentDeltaPayload)}\n\n`;

              // 如果累积的jsonAssemblyBuffer明显不是JSON或已处理为非工具调用JSON，则重置它
              if (!bufferStripped.startsWith('{')) {
                jsonAssemblyBuffer = '';
              } else if (possibleToolCall === false && bufferStripped.endsWith('}')) {
                jsonAssemblyBuffer = ''; // 是完整JSON但非工具调用，已作为文本发送
              }
            }
          }
        } // 结束 if (trimmedLine.startsWith("data:"))
      } // 结束 while ((newlineIndex = lineBuffer.indexOf('\n')) >= 0) -> 内层行处理循环
    } // 结束 while (true) -> 外层读取器循环
  } catch (e) {
    // 流处理过程中发生异常
    console.error(`流处理异常: ${e.message}`, e.stack);
    if (!toolCallDetectedAndSent) {
      // 如果未发送工具调用，则发送错误块
      const errorChunk = {
        id: streamId,
        object: 'chat.completion.chunk',
        created: Math.floor(Date.now() / 1000),
        model: originalModel,
        choices: [{ index: 0, delta: { role: 'assistant', content: `流处理异常: ${e.message}` }, finish_reason: 'stop' }],
      };
      try {
        yield `data: ${JSON.stringify(errorChunk)}\n\n`;
      } catch (finalError) {
        /* 忽略最终错误报告中的错误 */
      }
    }
  } finally {
    // 确保流结束时发送必要的标记
    if (!toolCallDetectedAndSent) {
      // 如果没有工具调用或[DONE]标记（已在内部处理并设置toolCallDetectedAndSent=true），则发送正常的停止标记
      console.log('[调试] 流已完成但未发送工具调用，发送finish_reason=stop。');
      const finalStopChunk = {
        id: streamId,
        object: 'chat.completion.chunk',
        created: Math.floor(Date.now() / 1000),
        model: originalModel,
        choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
      };
      yield `data: ${JSON.stringify(finalStopChunk)}\n\n`;
    }
    // 发送OpenAI兼容的最终SSE [DONE]消息
    yield `data: [DONE]\n\n`;
    console.log('[调试] 已向客户端发送最终的[DONE]。');
  }
}

export default {
  async fetch(request, env, ctx) {
    // 从请求头中获取OnDemand API密钥
    const authorizationHeader = request.headers.get('authorization');
    let onDemandApiKey = null;

    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
      onDemandApiKey = authorizationHeader.replace('Bearer ', ''); // 移除 "Bearer " 前缀
    }

    if (!onDemandApiKey) {
      // 如果未提供API密钥或格式不正确
      return new Response(JSON.stringify({ error: 'Authorization header (Bearer token) is missing or invalid.' }), {
        status: 401, // 未授权
        headers: { 'Content-Type': 'application/json' },
      });
    }

    let keyArr = onDemandApiKey.split(",");
    onDemandApiKey = keyArr[Math.floor(Math.random() * keyArr.length)]
    console.log("use : " + onDemandApiKey);


    // 用于OnDemand API调用的请求头，包含从请求中提取的API密钥
    const onDemandRequestHeaders = {
      'Content-Type': 'application/json',
      apikey: onDemandApiKey,
    };

    const url = new URL(request.url); // 解析请求URL

    // 处理聊天完成端点
    if (url.pathname === '/v1/chat/completions' && request.method === 'POST') {
      try {
        const openAIRequest = await request.json(); // 解析OpenAI格式的请求体
        console.log(`[调试] 原始请求JSON: ${JSON.stringify(openAIRequest, null, 2)}`);

        let sessionIdentifier = 'anonymous1'; // 默认会话标识符
        // let firstUserMessageContent = null;
        // // 从用户消息内容生成会话标识符 (SHA256哈希)
        // if (openAIRequest.messages) {
        //   for (const msg of openAIRequest.messages) {
        //     if (msg.role === 'user' && msg.content) {
        //       if (Array.isArray(msg.content)) {
        //         const textItem = msg.content.find((item) => item.type === 'text');
        //         if (textItem) firstUserMessageContent = textItem.text;
        //       } else {
        //         firstUserMessageContent = msg.content;
        //       }
        //       if (firstUserMessageContent) break; // 找到第一个用户消息内容后即停止
        //     }
        //   }
        // }
        // if (firstUserMessageContent) {
        //   sessionIdentifier = await sha256(String(firstUserMessageContent));
        // }
        // console.log(
        //   `会话标识符: ${sessionIdentifier} (基于用户消息: ${firstUserMessageContent ? String(firstUserMessageContent).substring(0, 50) + '...' : 'N/A'})`,
        // );

        // 获取或创建OnDemand会话ID，传入提取的API密钥
        const sessionInfo = await getOndemandSessionId(sessionIdentifier, onDemandApiKey, env);
        const sessionId = sessionInfo.sessionId;
        console.log("session id : " + sessionId)
        const isNewSession = sessionInfo.isNewSession;
        // 创建OnDemand API负载，传入提取的API密钥
        const ondemandPayload = await createOndemandPayload(openAIRequest, sessionId, isNewSession, onDemandApiKey, env);

        if (openAIRequest.stream) {
          // 处理流式请求
          // 传入包含API密钥的onDemandRequestHeaders
          const stream = streamOndemandResponse(sessionId, ondemandPayload, onDemandRequestHeaders, openAIRequest.model, env);
          // 返回SSE响应
          return new Response(
            new ReadableStream({
              async start(controller) {
                for await (const chunk of stream) {
                  controller.enqueue(new TextEncoder().encode(chunk));
                }
                controller.close();
              },
            }),
            { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' } },
          );
        } else {
          // 处理同步请求
          const queryUrl = `${ONDEMAND_API_BASE_URL}/chat/v1/sessions/${sessionId}/query`;
          // 使用包含API密钥的onDemandRequestHeaders进行fetch调用
          const onDemandResponse = await fetch(queryUrl, {
            method: 'POST',
            headers: onDemandRequestHeaders,
            body: JSON.stringify(ondemandPayload),
            // timeout: 120000 // Cloudflare Workers fetch不支持timeout选项，需通过AbortController处理
          });

          if (!onDemandResponse.ok) {
            const errorBody = await onDemandResponse.text();
            // 如果未提供API密钥或格式不正确
            return new Response(JSON.stringify({ error: errorBody }), {
              status: onDemandResponse.status, // 未授权
              headers: { 'Content-Type': 'application/json' },
            });
          }

          const data = await onDemandResponse.json();
          const ondemandData = data?.data || {};
          let answer = ondemandData.answer || '';
          console.log(`[调试] 同步响应答案: ${answer}`);

          let responseMessageRole = 'assistant';
          let responseMessageContent = answer;
          let responseMessageToolCalls = null;
          let finishReason = 'stop';

          // 尝试从同步响应的答案中解析工具调用
          if (answer && typeof answer === 'string' && answer.trim().startsWith('{') && answer.trim().endsWith('}')) {
            try {
              const parsedJson = JSON.parse(answer.trim());
              if (parsedJson && typeof parsedJson === 'object' && Array.isArray(parsedJson.tool_calls)) {
                const isValidFormat = parsedJson.tool_calls.every(
                  (call) => call && typeof call === 'object' && call.id && call.type && call.function,
                );
                if (isValidFormat) {
                  responseMessageToolCalls = parsedJson.tool_calls;
                  responseMessageContent = null; // 如果有工具调用，OpenAI规范中content应为null
                  finishReason = 'tool_calls';
                  console.log(`[调试] 从同步响应中解析到工具调用:`, responseMessageToolCalls);
                } else {
                  console.log("[调试] 解析了JSON，但'tool_calls'格式无效。");
                }
              } else {
                console.log("[调试] 解析了JSON，但未找到'tool_calls'键或其不是数组。");
              }
            } catch (e) {
              console.log('[调试] 答案看起来像JSON但解析失败。', e.message);
            }
          }

          // 构建OpenAI格式的完成响应对象
          const openaiCompletion = {
            id: `chatcmpl-${crypto.randomUUID()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: openAIRequest.model,
            choices: [
              {
                index: 0,
                message: {
                  role: responseMessageRole,
                  content: responseMessageContent,
                  tool_calls: responseMessageToolCalls,
                },
                finish_reason: finishReason,
              },
            ],
            usage: {
              // OnDemand API可能不提供此信息，因此设为null
              prompt_tokens: null,
              completion_tokens: null,
              total_tokens: null,
            },
            system_fingerprint: null, // 可选字段
          };
          return new Response(JSON.stringify(openaiCompletion), { headers: { 'Content-Type': 'application/json' } });
        }
      } catch (error) {
        // 捕获处理过程中的异常
        console.error('在 /v1/chat/completions 中出错:', error.message, error.stack);
        return new Response(JSON.stringify({ error: error.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } else if (url.pathname === '/v1/models' && request.method === 'GET') {
      // 处理模型列表端点
      const modelCards = [];
      const fixedCreatedTime = 1686935002; // 与Python代码一致的固定创建时间
      for (const modelId in MODEL_TO_ENDPOINT_MAP) {
        if (modelId !== 'default') {
          // 不包括"default"条目
          modelCards.push({
            id: modelId,
            object: 'model',
            created: fixedCreatedTime,
            owned_by: 'on-demand-adapter', // 适配器所有
          });
        }
      }
      modelCards.sort((a, b) => a.id.localeCompare(b.id)); // 按ID排序
      return new Response(JSON.stringify({ object: 'list', data: modelCards }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } else if (url.pathname === '/health' && request.method === 'GET') {
      // 处理健康检查端点
      return new Response(JSON.stringify({ status: 'ok' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 如果请求的路径和方法不匹配任何已知端点，则返回404
    return new Response('Not Found', { status: 404 });
  },
};
