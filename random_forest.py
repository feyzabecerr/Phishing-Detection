from features import main
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def getResult(url):

    #Importing dataset
    data = pd.read_csv("data.csv")
    data = data.drop([0], axis = 0) #removing unwanted column
    X = data.iloc[: , :-1].values
    y = data.iloc[:, -1].values
    #print(X)


    #Seperating training features, testing features, training labels & testing labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2)
    rand_forest = RandomForestClassifier()
    rand_forest.fit(X_train, y_train)
    score = rand_forest.score(X_test, y_test)
    print("Accuracy : " + str(score*100))

    X_final=main(url)

    X_final = np.array(X_final).reshape(1,-1)
    
    try:
        predict = rand_forest.predict(X_final)
        print(predict)
        if predict == -1:
            return "Phishing Url"
        else:
            return "Legitimate Url"
    except:
        return "Phishing Url"

