export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Serve the website's static files
    if (url.pathname === "/") {
      return env.ASSETS.fetch(request);
    }

    // API health check
    if (url.pathname === "/api/health" && request.method === "GET") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return Response.json({
          success: true,
          project: "VideoCash-New",
          database: result?.connected === 1 ? "connected" : "unknown"
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            project: "VideoCash-New",
            error: "Database connection failed"
          },
          { status: 500 }
        );
      }
    }

    // Language preference endpoint
    if (url.pathname === "/api/config" && request.method === "GET") {
      return Response.json({
        success: true,
        project: "VideoCash-New",
        languages: ["en", "ru"],
        platforms: [
          "Facebook",
          "Instagram",
          "WhatsApp",
          "X",
          "Telegram",
          "Snapchat",
          "Likee",
          "TikTok",
          "VK",
          "LinkedIn",
          "Threads",
          "Quora",
          "Pinterest",
          "YouTube"
        ],
        rewardsEnabled: false,
        withdrawalsEnabled: false
      });
    }

    return Response.json(
      { success: false, error: "Not found" },
      { status: 404 }
    );
  }
};