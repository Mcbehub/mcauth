ENDPOINTS = {
    'minecraft_java': {
        'XSTS_RELYING_PARTY': 'rp://api.minecraftservices.com/',
        'login_with_xbox': 'https://api.minecraftservices.com/authentication/login_with_xbox'
    },
    'minecraft_bedrock': {
        'XSTS_RELYING_PARTY': 'https://multiplayer.minecraft.net/',
        'authenticate': 'https://multiplayer.minecraft.net/authentication',
        'servicesSessionStart': 'https://authorization.franchise.minecraft-services.net/api/v1.0/session/start'
    },
    'xbox': {
        'user_auth': 'https://user.auth.xboxlive.com/user/authenticate',
        'xsts_authorize': 'https://xsts.auth.xboxlive.com/xsts/authorize'
    },
    'live': {
        'device_code_request': 'https://login.live.com/oauth20_devicecode',
        'token_request': 'https://login.live.com/oauth20_token.srf'
    }
}

XBOX_ERRORS = {
    2148916227: 'Account banned by Xbox',
    2148916233: 'No Xbox account found',
    2148916234: 'Xbox terms not accepted',
    2148916235: 'Region not authorized',
    2148916236: 'Age verification needed',
    2148916237: 'Account limited',
    2148916238: 'Child account needs adult'
}

DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    'User-Agent': 'MinecraftLauncher/2.2.10675'
}
