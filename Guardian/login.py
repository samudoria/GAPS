from Infra.util import *


def login_tripadvisor(username, password):
    adb_pm(
        "grant com.tripadvisor.tripadvisor android.permission.ACCESS_COARSE_LOCATION"
    )
    adb_pm(
        "grant com.tripadvisor.tripadvisor android.permission.ACCESS_FINE_LOCATION"
    )
    if not wait_for_activity(
        ["RebrandOnboardingActivity", "TASignInActivity"], 5
    ):
        return False

    cur_act = get_current_activity()
    if "RebrandOnboardingActivity" in cur_act:
        # close button
        adb_input("tap 710 98", 1)

    # input()

    # username
    adb_input("tap 540 660", 0.5)
    adb_input("text " + username, 0.5)
    adb_input("tap 540 660", 0.5)
    # password
    adb_input("keyevent KEYCODE_TAB", 0.5)
    adb_input("text " + password, 0.5)
    # login
    adb_input("tap 730 100", 5)
    adb_input("tap 384 962", 2)
    adb_input("tap 570 715", 2)

    return not check_activity("TASignInActivity")


def login_evernote(username, password):
    # username
    adb_input("tap 500 700", 1)
    adb_input("text " + username, 1)
    # continue
    adb_input("tap 500 800", 5)
    # password
    adb_input("text " + password, 1)
    # sign in
    adb_input("tap 500 900", 10)
    if not wait_for_activity("NewPhoneMainActivity", 5):
        print("wrong activity after login")
        return False
    return True


def login_yelp(username=None, password=None):
    adb_pm("grant com.yelp.android android.permission.ACCESS_COARSE_LOCATION")
    adb_pm("grant com.yelp.android android.permission.ACCESS_FINE_LOCATION")
    adb_pm("grant com.yelp.android android.permission.CAMERA")

    if not wait_for_activity("ActivityOnboarding", 5):
        return False
    adb_input("tap 500 1100", 1)
    # skip
    adb_input("tap 664 120", 1)
    restart_app("com.yelp.android")
    adb_input("tap 528 1099", 1)

    return check_activity("ActivityNearby")


def login_spotify(username, password):
    if not wait_for_activity(
        "com.spotify.mobile.android.service.LoginActivity", 5
    ):
        return False

    adb_input("tap 360 1040", 0.5)
    adb_input("tap 360 458", 0.5)
    adb_input("text " + username, 0.5)
    adb_input("keyevent KEYCODE_TAB", 0.5)
    adb_input("text " + password, 0.5)
    adb_input("keyevent KEYCODE_ENTER", 10)

    return not check_activity(
        "com.spotify.mobile.android.service.LoginActivity"
    )


def login_quizlet(username, password):
    print("executing login script")
    if not wait_for_activity("ui.intro.IntroActivity"):
        return False

    adb_input("tap 500 1100", 1)
    # adb_input("tap 500 400", 0.5)
    adb_input("text " + username, 0.5)
    adb_input("keyevent KEYCODE_TAB", 0.5)
    # adb_input("tap 500 350", 0.5)
    adb_input("text " + password, 0.5)
    adb_input("tap 360 837", 3)

    if not wait_for_activity("EdgyDataCollectionWebActivity", 2):
        return False

    adb_input("tap 640 104", 1)
    return check_activity("HomeNavigationActivity")


def login_goodrx(username=0, password=0):
    adb_input("tap 360 944", 1)


def login_linewebtoon(username=0, password=0):
    time.sleep(2)
    adb_input("tap 693 111", 1)
    adb_input("tap 360 1070", 3)
    # adb_input("tap 600 1128", 1)


def login_googletranslate(username=0, password=0):
    adb_input("tap 655 968", 1)
    adb_input("tap 655 968", 1)


def login_ucbrowser(username=0, password=0):
    adb_input("tap 360 1090", 1)


def login_merriamwebster(username=0, password=0):
    adb_tap_center("[518,728][646,824]")


def login_googlechrome(username=0, password=0):
    adb_input("tap 384 1100", 5)
    adb_input("tap 120 1100", 1)


def login_accuweather(username=0, password=0):
    adb_input("tap 384 1100", 2)
    adb_input("tap 600 742", 2)
    adb_input("tap 600 700", 3)
    adb_input("tap 600 780", 7)
    # input('waiting for the last step')
    # adb_input("tap 56 104")


def login_autoscout24(username=0, password=0):
    time.sleep(3)
    adb_input("tap 564 1111", 3)


def login_duolingo(username=0, password=0):
    adb_input("tap 378 1032")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("text " + username)
    adb_input("keyevent KEYCODE_TAB")
    adb_input("text " + password)
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_ENTER", 5)


def login_evernote(username=0, password=0):
    adb_input("text " + username)
    adb_input("tap 350 820")
    adb_input("text " + password)
    adb_input("tap 350 900", 8)


def login_marvelcomics(username=0, password=0):
    adb_input("tap 50 100")


def login_zedge(username=0, password=0):
    adb_input("tap 384 960", 12)


def login_bbcnews(username=0, password=0):
    adb_input("tap 586 744")
    adb_input("tap 630 770")


def login_diary(username=0, password=0):
    adb_input("tap 360 230")
    adb_input("tap 360 1150")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("text " + username)
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_TAB")
    adb_input("text " + password)
    adb_input("keyevent KEYCODE_TAB")
    adb_input("keyevent KEYCODE_ENTER", 5)
    adb_input("tap 360 1100", 5)


def login_chanelweather(username=0, password=0):
    adb_input("tap 640 780")
    adb_input("tap 360 1000")
    adb_input("tap 564 715", 5)
    adb_input("tap 460 740", 5)


def login_devweather(username=0, password=0):
    adb_input("tap 360 950")
    adb_input("tap 564 715", 8)


def login_dominos(username=0, password=0):
    pass


def login_googlenews(username=0, password=0):
    pass


def login_calendar(username=0, password=0):
    pass


def login_gmail(username=0, password=0):
    pass


def login_soundhound(username=0, password=0):
    adb_input("tap 572 693")


def login_photomath(username=0, password=0):
    adb_input("tap 82 1110")
    adb_input("tap 564 720")


def login_transit(username=0, password=0):
    adb_input("tap 388 1030")
    adb_input("tap 560 713")


def login_ted(username=0, password=0):
    time.sleep(10)
    adb_input("tap 400 700")
    adb_input("tap 200 210")
    adb_input("tap 385 1075")
    adb_input("tap 385 255")
    adb_input("tap 385 1050")
    adb_input("tap 385 1120")


def login_shein(username=0, password=0):
    adb_input("tap 385 890")
    adb_input("tap 695 272")


def login_castbox(username=0, password=0):
    adb_input("tap 400 1050", 1)
    adb_input("tap 400 1050", 1)
    adb_input("tap 400 1050", 1)
    adb_input("tap 400 1050", 1)
    adb_input("tap 520 920", 1)
    adb_input("tap 400 1050")


def login_nasa(username=0, password=0):
    adb_input("tap 624 1080")
    adb_input("tap 346 758")


def login_onx(username=0, password=0):
    time.sleep(10)
    adb_input("tap 400 700")
    adb_input("tap 172 840")
    adb_input("text " + username)
    adb_input("tap 172 1000")
    adb_input("text " + password)
    adb_input("tap 172 1130")
    time.sleep(3)
    adb_input("tap 400 840")


def login_espn(username=0, password=0):
    time.sleep(5)
    adb_input("tap 400 800")
    time.sleep(10)
    adb_input("tap 550 950")
    time.sleep(3)
    adb_input("tap 300 650")
    adb_input("text " + username)
    adb_input("tap 300 800")
    time.sleep(3)
    adb_input("tap 350 920")
    adb_input("text " + password)
    adb_input("tap 400 1050")
    time.sleep(3)
    code = input("input the code from email\n")
    adb_input("text " + code)
    adb_input("tap 400 800")
    time.sleep(8)
    adb_input("tap 700 1130")
    time.sleep(1)
    adb_input("tap 700 1130")
    time.sleep(1)
    adb_input("tap 700 1130")
    time.sleep(1)
    adb_input("tap 670 700")
    time.sleep(3)


def login_audible(username=0, password=0):
    time.sleep(10)
    adb_input("tap 400 850")
    time.sleep(10)
    adb_input("tap 400 250")
    adb_input("text " + username)
    adb_input("tap 400 350")
    adb_input("text " + password)
    adb_input("tap 400 600")
    time.sleep(10)


def login_etsy(username=0, password=0):
    time.sleep(5)
    adb_input("tap 700 650")
    adb_input("tap 300 850")
    adb_input("text " + username)
    adb_input("tap 400 950")
    time.sleep(10)
    adb_input("tap 300 570")
    adb_input("text " + password)
    adb_input("tap 400 800")
    time.sleep(10)
    adb_input("tap 400 980")
    time.sleep(3)
    adb_input("tap 400 830")


def login_app(apk: str):
    print("login")
    time.sleep(1)
    if f"login_{apk}" not in globals():
        return True
    flag = globals()[f"login_{apk}"](*get_account(apk))
    if flag is None:
        return True
    return flag
