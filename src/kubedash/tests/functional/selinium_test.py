from selenium import webdriver
import time

#def test_lambdatest_google():
#    driver = webdriver.Chrome()
#    driver.maximize_window()
#    driver.get('https://duckduckgo.com/')
#    # driver.get("https://google.co.in / search?q = geeksforgeeks")
#    if not "DuckDuckGo" in driver.title:
#        raise Exception("Could not load page")
#    time.sleep(3)
#    element = driver.find_element("name", "q")
#    element.send_keys("LambdaTest")
#    element.submit()
#    time.sleep(3)
#    ## Check if the LambdaTest Home Page is open
#    title = "Most Powerful Cross Browser Testing Tool Online | LambdaTest"
#    lt_link = driver.find_element("xpath", "/html/body/div[2]/div[5]/div[3]/div/div[1]/div[6]/div[1]/article/div[2]/h2/a/span")
#    lt_link.click()
#    time.sleep(5)
#    assert title == driver.title
#    driver.quit()
#
# https://www.geeksforgeeks.org/selenium-python-tutorial/