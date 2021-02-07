class Config:
    USER_AGENT = ''
    APP_VERSION = '2.3.0'
    IDLIST_PATH = './data/idlist.txt'
    ACCOUNT_PATH = './data/account.txt'
    URL = {
        'mmt_url': 'https://webapi.account.mihoyo.com/Api/create_mmt?scene_type=1&now={}&reason=bbs.mihoyo.com',
        'cookie_url' : 'https://webapi.account.mihoyo.com/Api/cookie_accountinfo_by_loginticket?login_ticket={}&t={}',
        'login_url' : 'https://webapi.account.mihoyo.com/Api/login_by_password',
        'get_chars_url' : 'https://api-takumi.mihoyo.com/game_record/genshin/api/index?server=cn_gf01&role_id={0}',
        'get_abyss_url' : 'https://api-takumi.mihoyo.com/game_record/genshin/api/spiralAbyss?schedule_type={}&server=cn_gf01&role_id={}',
        'post_chars_url' : 'https://api-takumi.mihoyo.com/game_record/genshin/api/character',
        
    }
    REFERER = [
         'https://webstatic.mihoyo.com/',
         'https://bbs.mihoyo.com/',
        ]
CONFIG = Config()
REFERER = CONFIG.REFERER