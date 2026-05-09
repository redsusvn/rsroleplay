/**

rename this file to worker.js or edit the hello world file to this
after that go to the settings tab. add ACCOUNT_ID, API_TOKEN and GATEWAY_KEY in your Variables and Secrets setitngs
the account id is in the html link on your cloudflare website like this
https://dash.cloudflare.com/d4828ca376958c28150bf99adec26c93/workers/
paste in the variable d4828ca376958c28150bf99adec26c93 and it will be your account id
for api token, click on user icon -> profile -> api token -> create token -> worker ai -> Account Resources click the select and click your email -> Create token -> copy token and paste in API_TOKEN
GATEWAY_KEY you can set to anything you like
in RSROLEPLAY engine page, click api endpoints -> add endpoint -> provider format will be custom api, modal id google/gemma-4-26b-a4b-it -> api url is your worker url with /v1/chat/completions in the end like https://demo.youremail.workers.dev/v1/chat/completions -> mode to chat or summarize, based on your usage -> api key is the value you set in GATEWAY_KEY
happy roleplay!

 */
function errorToAiResponse(message, isStream) {
  const errorMessage = `[Gateway Error]: ${message}`;
  
  if (isStream) {
    // Format specifically for your backend's createUnifiedStream parser
    const payload = JSON.stringify({
      choices: [{
        delta: { content: errorMessage }
      }]
    });
    return new Response(`data: ${payload}\n\ndata: [DONE]\n\n`, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  // Format for standard non-stream JSON response
  return new Response(JSON.stringify({
    choices: [{
      message: {
        role: "assistant",
        content: errorMessage
      }
    }]
  }), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

export default {
  async fetch(request, env) {
    // 1. Handle CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    const url = new URL(request.url);
    let isStreamRequest = false;

    try {
      // Attempt to peek if streaming is requested to handle errors correctly
      const clonedRequest = request.clone();
      try {
        const json = await clonedRequest.json();
        isStreamRequest = json.stream === true;
      } catch (e) {
        // If body isn't JSON, we handle it in the main routing
      }

      // 2. Auth Check (GATEWAY_KEY)
      if (env.GATEWAY_KEY) {
        const authHeader = request.headers.get("Authorization");
        if (!authHeader || authHeader !== `Bearer ${env.GATEWAY_KEY}`) {
          return errorToAiResponse(`Unauthorized: The GATEWAY_KEY you provided in the backend settings does not match the Worker's environment variable.`, isStreamRequest);
        }
      }

      // 3. Path Routing
      if (url.pathname === "/v1/models") {
        return new Response(JSON.stringify({
          object: "list",
          data: [{
            id: "google/gemma-4-26b-a4b-it",
            object: "model",
            created: 1715641200,
            owned_by: "cloudflare"
          }]
        }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      }

      if (url.pathname !== "/v1/chat/completions") {
        return errorToAiResponse(`Invalid Path: ${url.pathname}. Ensure your Backend "Custom URL" ends with /v1/chat/completions`, isStreamRequest);
      }

      const body = await request.json();
      const internalModel = "@cf/google/gemma-4-26b-a4b-it";
      const displayModel = "google/gemma-4-26b-a4b-it";

      if (!env.ACCOUNT_ID || !env.API_TOKEN) {
        return errorToAiResponse("Missing Cloudflare Credentials: Check ACCOUNT_ID and API_TOKEN in Worker Variables.", isStreamRequest);
      }

      const cfAiUrl = `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/ai/v1/chat/completions`;

      const cfResponse = await fetch(cfAiUrl, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.API_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: internalModel,
          messages: body.messages,
          stream: body.stream || false,
          max_tokens: body.max_tokens || 4096,
          temperature: body.temperature || 0.85,
          top_p: body.top_p || 0.95,
        }),
      });

      // If Cloudflare returns an error (400, 401, 429, etc.)
      if (!cfResponse.ok) {
        const errorText = await cfResponse.text();
        return errorToAiResponse(`Cloudflare AI Error (${cfResponse.status}): ${errorText}`, isStreamRequest);
      }

      // 4. Handle Streaming Successful Response
      if (body.stream) {
        const { readable, writable } = new TransformStream({
          transform(chunk, controller) {
            const text = new TextDecoder().decode(chunk);
            // Replace internal CF model strings with display names to maintain abstraction
            const maskedText = text.replace(new RegExp(internalModel, 'g'), displayModel);
            controller.enqueue(new TextEncoder().encode(maskedText));
          }
        });
        
        cfResponse.body.pipeTo(writable);

        return new Response(readable, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Access-Control-Allow-Origin": "*",
          },
        });
      } 
      
      // 5. Handle Standard Successful Response
      const data = await cfResponse.json();
      if (data.model) data.model = displayModel;

      return new Response(JSON.stringify(data), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });

    } catch (err) {
      return errorToAiResponse(`Worker Exception: ${err.message}`, isStreamRequest);
    }
  },
};
