import os

dictionary = "whoami"
indexes = [0, 1, 2, 3, 2, 6, 2, 4, 5, 6, 0, 7, 1337]
final = ""

for index in indexes:
    if index == 1337:
        break
    final += dictionary[index]
os.system(final)
