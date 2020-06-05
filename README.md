# Fuzzer

Project realised for the cours: Computer System Security
- Rémy Detobel
- NOMA: `99841900`    
(Github link: https://github.com/detobel36/fuzzer)[https://github.com/detobel36/fuzzer]


## Vulnerabilities

- `success_Version_80.img`    
    The program carsh if version is between 80 and 100. 

- `success_Header_ID_117.img`    
    The program crash if an header id have value 117

- `success_Comment_Size_1641.img`    
    The program carsh if a comment have a size bigger than 1641 character. Notice that the converter
    have a protection for big number.

- `success_Author_Character_28197.img`    
    The program crash on specific character in author name.   
    Notice that this work also for Comment (see `success_Comment_Character_29952.img`)

- `success_Height_ffffffff.img`    
    The program crash if height have the value "ffff ffff".


**BONUS**

- `success_Comment_Character_29952.img`    
    Like already mention it is the same bug that `success_Author_Character_28197.img`

- `success_Color_Value_117.img`    
    The program carsh if there is one color in addition in the color table and that this color
    finish with the byte 75. It it the same bug that in `success_Header_ID_117.img`. The color
    in addition will replace the "header" value and thus make crash the program.


## Execute

```BASH
python3 fuzzer.py
```

To view help:
```BASH
python3 fuzzer.py --help
```


## Python modules used
This python code use the following modules: `os`, `sys`, `subprocess`, `argparse`
