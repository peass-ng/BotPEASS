# BotPEASS

![](https://github.com/carlospolop/BotPEASS/raw/main/images/botpeas.png)

Use this bot to monitor new CVEs containing defined keywords and send alerts to Slack and/or Telegram.

## See it in action

Join the Telegram group **[peass](https://t.me/peass)** to see the bot in action and be up to date with the latest privilege escalation vulnerabilities.

## Configure one for yourself

**Configuring your own BotPEASS** that notifies you about the new CVEs containing specific keywords is very easy!

- Fork this repo
- Modify the file `config/bopteas.yaml` and set your own keywords
- In the **github secrets** of your forked repo enter the following API keys:
    - **VULNERS_API_KEY**: (Optional) This is used to find publicly available exploits. You can use a Free API Key.
    - **SLACK_WEBHOOK**: (Optional) Set the Slack webhook to send messages to your Slack group.
    - **DISCORD_WEBHOOK_URL**: (Optional) Set the Discord webhook to send messages to your Discord channel.
    - **TELEGRAM_BOT_TOKEN** and **TELEGRAM_CHAT_ID**: (Optional) Your Telegram bot token and the chat_id to send the messages to.
- Check `.github/wordflows/bopteas.yaml` and configure the cron (*once every 8 hours by default*)

*Note that the Slack, Telegram, and Discord configurations are optional, but if you don't set any of them you won't receive any notifications anywhere*
