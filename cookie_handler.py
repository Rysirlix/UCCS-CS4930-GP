import undetected_chromedriver as uc
import json
import time

# Install: pip install undetected-chromedriver

print("=== Complete Cookie & Storage Analysis for Amazon ===\n")

try:
    print("Starting Chrome browser...")
    
    options = uc.ChromeOptions()
    options.add_argument('--headless=new')  # Run without showing browser
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    
    driver = uc.Chrome(options=options, version_main=142)
    print("✓ Browser started successfully\n")
    
    # Navigate to Amazon
    amazon_url = "https://www.amazon.com"
    print(f"Navigating to {amazon_url}...")
    driver.get(amazon_url)
    print("✓ Page loaded\n")
    
    # Wait for page and let it settle
    time.sleep(8)
    
    print("Current URL:", driver.current_url)
    print("\n" + "="*70)
    
    # 1. Get HTTP Cookies
    print("\n1. HTTP COOKIES (from Set-Cookie headers)")
    print("-"*70)
    cookies = driver.get_cookies()
    print(f"Found: {len(cookies)} cookies\n")
    
    cookie_data = {}
    for cookie in cookies:
        name = cookie['name']
        cookie_data[name] = cookie
        print(f"  • {name}")
    
    # 2. Get localStorage
    print("\n" + "="*70)
    print("2. LOCAL STORAGE")
    print("-"*70)
    try:
        local_storage = driver.execute_script("""
            let items = {};
            for (let i = 0; i < localStorage.length; i++) {
                let key = localStorage.key(i);
                items[key] = localStorage.getItem(key);
            }
            return items;
        """)
        print(f"Found: {len(local_storage)} items\n")
        for key in local_storage.keys():
            print(f"  • {key}")
    except Exception as e:
        print(f"Could not access localStorage: {e}")
        local_storage = {}
    
    # 3. Get sessionStorage
    print("\n" + "="*70)
    print("3. SESSION STORAGE")
    print("-"*70)
    try:
        session_storage = driver.execute_script("""
            let items = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                let key = sessionStorage.key(i);
                items[key] = sessionStorage.getItem(key);
            }
            return items;
        """)
        print(f"Found: {len(session_storage)} items\n")
        for key in session_storage.keys():
            print(f"  • {key}")
    except Exception as e:
        print(f"Could not access sessionStorage: {e}")
        session_storage = {}
    
    # 4. Check for cookies in document.cookie
    print("\n" + "="*70)
    print("4. DOCUMENT.COOKIE (JavaScript accessible cookies)")
    print("-"*70)
    try:
        doc_cookies = driver.execute_script("return document.cookie;")
        if doc_cookies:
            doc_cookie_list = [c.strip().split('=')[0] for c in doc_cookies.split(';')]
            print(f"Found: {len(doc_cookie_list)} cookies\n")
            for name in doc_cookie_list:
                print(f"  • {name}")
        else:
            print("No JavaScript-accessible cookies found")
    except Exception as e:
        print(f"Could not access document.cookie: {e}")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("-"*70)
    total_items = len(cookies) + len(local_storage) + len(session_storage)
    print(f"HTTP Cookies: {len(cookies)}")
    print(f"localStorage items: {len(local_storage)}")
    print(f"sessionStorage items: {len(session_storage)}")
    print(f"Total storage items: {total_items}")
    
    # Save everything to file
    all_data = {
        "http_cookies": cookies,
        "local_storage": local_storage,
        "session_storage": session_storage,
        "total_count": total_items
    }
    
    with open('amazon_all_storage.json', 'w') as f:
        json.dump(all_data, f, indent=2)
    
    print("\n✓ All data saved to amazon_all_storage.json")
    
    # Show detailed cookie info
    print("\n" + "="*70)
    print("DETAILED COOKIE INFORMATION")
    print("-"*70)
    for cookie in cookies:
        print(f"\n{cookie['name']}:")
        print(f"  Value: {cookie['value'][:50]}..." if len(cookie['value']) > 50 else f"  Value: {cookie['value']}")
        print(f"  Domain: {cookie.get('domain')}")
        print(f"  Secure: {cookie.get('secure')}")
        print(f"  HttpOnly: {cookie.get('httpOnly')}")
    
    time.sleep(3)
    
    try:
        driver.quit()
    except:
        pass
    print("\n✓ Browser closed successfully")
    
except Exception as e:
    print(f"\n❌ Error: {type(e).__name__}")
    print(f"Details: {str(e)}")