from features import main
from random_forest import getResult
import pandas as pd

if __name__ == '__main__' :
    
    df = pd.read_csv("urls.csv")
    result = df["url"]
    print(result)
    detect = list()
   
    for i in result:
        detect.append(getResult(i))
        print(i)

    df.to_csv("urls.csv", index = False)
    df["Detect Result"] = detect
    df.to_csv("result.csv", index = False)



