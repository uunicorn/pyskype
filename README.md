In src/ edit cred.py to provide skypename and password. Start with 

$ python
>>> from logger import *
.....
>>>

Once connected you can send messages to users/circles with
>>> msgr(routing("8:" + skypename) + reliability() + messaging_rich("Oh, hi!"))
