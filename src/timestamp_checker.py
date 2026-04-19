import datetime


def check_timestamp(timestamp):
    print("\n[+] TIMESTAMP ANALYSIS")
    print(f"    {'-'*40}")

    # Convert raw timestamp to readable date
    try:
        date = datetime.datetime.utcfromtimestamp(timestamp)
        year = date.year
        print(f"    Raw Value     : {hex(timestamp)}")
        print(f"    Compiled Date : {date.strftime('%Y-%m-%d')}")
    except Exception as e:
        print(f"    [ERROR] Could not read timestamp: {e}")
        return None

    # Get current year to compare
    current_year = datetime.datetime.now().year

    # check if timestamp looks fake
    if timestamp == 0:
        status = "SUSPICIOUS"
        score  = 30
    elif year < 1995:
        status = "SUSPICIOUS - Too old to be real!"
        score  = 30
    elif year > current_year:
        status = "SUSPICIOUS - Future date, looks fake!"
        score  = 30
    else:
        status = "OK - Looks normal"
        score  = 0

    print(f"    Status        : {status}")
    print(f"    Risk Score    : +{score} points")

    return {
        "timestamp": timestamp,
        "date"     : str(date),
        "year"     : year,
        "status"   : status,
        "score"    : score
    }