#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Project 2 - Write a fuzzer
Computer System Security
Rémy Detobel
NOMA: 99841900

This file try follow the Google Style Guide
(https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html)
"""

import os
import sys
import subprocess
import argparse

DEFAULT_CONVERT_PATH = "./converter_linux_x8664"
DEFAULT_CONVERT_PATH_IF_FAIL = "./converter"
VERBOSE = False

class ABCImage:
    """Contains all information of an ABCImage. 

    This class could create an ABCImage but also execute the conversion and detect any problem.

    Args:
        imageDescription (str): Description of the current image.
        createdFile (str): Name of the file that will be create (input image). 
            By default: "tmp_testinput.img"
        outputFile (str): Name of the file after the conversion (output image).
            By default: "tmp_testoutput.img"
    """

    # Define header ID
    HEADER = {
        "author": bytearray((1).to_bytes(1, byteorder='little')),
        "comment": bytearray((12).to_bytes(1, byteorder='little')),
        "dimension": bytearray((2).to_bytes(1, byteorder='little')),
        "numberColor": bytearray((10).to_bytes(1, byteorder='little')),
        "color": bytearray((11).to_bytes(1, byteorder='little')),
        "end": bytearray((0).to_bytes(1, byteorder='little'))
    }

    # Define end of line byte (00)
    END_OF_LINE = bytearray((0).to_bytes(1, byteorder='little'))

    # Define the magic number that identify that it is an ABC Image
    MAGIC_NUMBER = bytearray.fromhex("abcd")

    def __init__(self, imageDescription, createdFile = "tmp_testinput.img", 
            outputFile = "tmp_testoutput.img"):
        self._imageDescription = imageDescription

        # By default version is 100
        self.setVersion(100)

        # Default 2x2 images from Ramin
        self.setDimension(2, 2)
        self.setComment("Hello")
        self.setAuthor("Ramin")
        self.setColorTableAndNumberOfColor(["00000000", "FFFFFF00"])
        self.setPixel(["00", "01", "01", "00"])
        self._extra = None

        self._createdFile = createdFile
        self._outputFile = outputFile

    def getImageDescription(self):
        """Get the desciption of the current image

        Returns:
            str: The image description
        """
        return self._imageDescription

    def getFormatedImageDescription(self):
        """Get formated description of the current image

        Returns:
            str: Description of the image where '_' have been replaced with space
        """
        return self.getImageDescription().replace('_', ' ')

    def setVersion(self, numVersion):
        """Define the version of the image

        This value will be convert to a bytearray of 2 bytes

        Args:
            numVersion (int): Number of the version
        """
        self._version = bytearray((numVersion).to_bytes(2, byteorder='little'))

    def setDimension(self, width, height):
        """Define the dimension of the image

        Both parameters will be convert to a bytearray of 4 bytes

        Args:
            width (int): the width of the image
            height (int): the height of the image
        """
        self.setManualWidth(bytearray((width).to_bytes(4, byteorder='little')))
        self.setManualHeight(bytearray((height).to_bytes(4, byteorder='little')))

    def setManualHeight(self, height):
        """Manually change the height of the image

        Unlink setDimension method, the height will not be convert

        Args:
            height (bytearray): the height
        """
        self._height = height

    def setManualWidth(self, width):
        """Manually change the width of the image

        Unlink setDimension method, the width will not be convert

        Args:
            width (bytearray): the width
        """
        self._width = width

    def setComment(self, comment):
        """Set the comment of the image

        Comment is convert to a bytearray followed by an END_OF_LINE

        Args:
            comment (str, optional): The comment (remove if None)
        """
        if(comment is None):
            self._comment = None
        else:
            self._comment = bytearray(comment.encode()) + self.END_OF_LINE

    def setManualComment(self, comment):
        """Manually set the comment of the image

        Unlike method setComment, the comment is not convert

        Args:
            comment (bytearray): The comment
        """
        self._comment = comment + self.END_OF_LINE

    def setAuthor(self, author):
        """Set the author of the image

        Author is convert to a bytearray followed by an END_OF_LINE

        Args:
            author (str): The author
        """
        self._author = bytearray(author.encode()) + self.END_OF_LINE

    def setManualAuthor(self, author):
        """Manually set the author of the image

        Unlike method setAuthor, the author is not convert

        Args:
            author (bytearray): The author
        """
        self._author = author + self.END_OF_LINE

    def setColorTableAndNumberOfColor(self, listColor):
        """Set number of color and color table of the image

        Args:
            listColor (:obj:`list` of `str`): List of color in hexadecimal
        """
        self.setNumberOfColor(len(listColor))
        self.setColorTable(listColor)

    def setNumberOfColor(self, numberColor):
        """Set the number of color

        The number of color is convert to a bytearray of 4 bytes

        Args:
            numberColor (int): The number of color
        """
        self._numberColor = bytearray((numberColor).to_bytes(4, byteorder='little'))

    def setManualNumberOfColor(self, numberColor):
        """Manually set the number of color

        Unlike method setNumberOfColor, the number of color is not convert

        Args:
            numberColor (bytearray): the number of color
        """
        self._numberColor = numberColor

    def setColorTable(self, listColor):
        """Set color table of the image

        Each string of the list is convert to bytearray (based on the fact that string is 
        in hexadecimal)
        
        Args:
            listColor (:obj:`list` of `str`): List of color in hexadecimal
        """
        self._listColor = bytearray()
        for color in listColor:
            self._listColor += bytearray.fromhex(color)

    def setManualColorTable(self, listColor):
        """Manually set color table of the image

        Unlike method setColorTable, the element of the list are not convert to bytearray

        Args:
            listColor (:obj:`list` of `bytearray`): List of color
        """
        self._listColor = bytearray()
        for color in listColor:
            self._listColor += color

    def setPixel(self, pixelList):
        """Set the pixel of the image

        Each element of the list are convert to bytearray (based on the fact that string are in
        hexadecimal)

        Args:
            pixelList (:obj:`list` of `str`): List of pixel
        """
        self._pixels = bytearray()
        for pixel in pixelList:
            self._pixels += bytearray.fromhex(pixel)

    def setExtraField(self, header, data = None):
        """Set an extra field

        Allow to add custom header id with custom data

        Args:
            header (bytearray): id of the header
            data (str, optional): data linked to this header (convert to bytearray)
        """
        self._extra = header
        if(data is not None):
            self._extra += bytearray(data.encode()) + self.END_OF_LINE

    def _getData(self):
        """Get all data of this image in byte

        These information could be used to directly save the image

        Returns:
            bytes: all bytes that represent this image
        """
        content = bytearray()
        content += self.MAGIC_NUMBER
        content += self._version
        content += self.HEADER['dimension'] + self._width + self._height
        if(self._comment is not None):
            content += self.HEADER['comment'] + self._comment

        content += self.HEADER['author'] + self._author
        content += self.HEADER['numberColor'] + self._numberColor
        content += self.HEADER['color'] + self._listColor
        if(self._extra is not None):
            content += self._extra
        content += self.HEADER['end']
        content += self._pixels
        return bytes(content)

    def _createFile(self):
        """Create the file of this image

        _createdFile contains the file name and method _getData give all information that need to
        be store in the file
        """
        test_file = open(self._createdFile, "wb")
        test_file.write(self._getData())
        test_file.close()

    def _convert(self, pathConverter):
        """Convert the current image

        Args:
            pathConverter (str, optional): Path to the converter tool
        """
        command = [pathConverter, self._createdFile, self._outputFile]
        try:
            executionResult = subprocess.check_output(command)
        except subprocess.CalledProcessError as e:
            self._runWithoutProblem = False
            self._convertResultMsg = str(e)
        else:
            self._runWithoutProblem = True
            self._convertResultMsg = executionResult
            if(VERBOSE):
                print("Output of " + str(self.getFormatedImageDescription()))
                print(self.getConvertResultMsg())

        try:
            os.remove(self._outputFile)
        except OSError:
            pass

    def haveBeenConvertWithoutProblem(self):
        """Know if the convertion of the file have run without any problem

        To have real result, the method _convert need to be executed before

        Returns:
            :bool: True if convertion work, False otherwise
        """
        return self._runWithoutProblem

    def getConvertResultMsg(self):
        """Get the result message of the conversion of this file

        To have real result, the method _convert need to be executed before

        Returns:
            :str: The result of the execution (output or error message)
        """
        return self._convertResultMsg.decode('utf-8')

    def _saveIfSuccessDeleteOtherwise(self):
        """Rename the file of this image if the conversion failed, otherwise delete this file
        """
        if(not self.haveBeenConvertWithoutProblem()):
            newName = "success_" + str(self.getImageDescription()) + ".img"
            os.rename(self._createdFile, newName)
            print("Save success file: " + str(self.getFormatedImageDescription()))
        else:
            try:
                os.remove(self._createdFile)
            except OSError:
                pass

    def runAll(self):
        """Create file, try to convert and save if conversion failed

        Returns:
            :bool: True if the conversion have run without problem, False otherwise
        """
        self._createFile()
        self._convert(DEFAULT_CONVERT_PATH)
        self._saveIfSuccessDeleteOtherwise()
        return self.haveBeenConvertWithoutProblem()


def createNormalImage():
    if(VERBOSE):
        print("Test normal image")

    normalImage = ABCImage("Normal")
    normalImage.runAll()
    
def testVersion(): # MATCH
    if(VERBOSE):
        print("Test different version")

    for testVersion in range(0, 256):
        versionImage = ABCImage("Version_" + str(testVersion))
        versionImage.setVersion(testVersion)
        if(not versionImage.runAll()):
            break;

def testHeader(): # MATCH
    if(VERBOSE):
        print("Test all header ID")

    for header in range(0, 256):
        headerImage = ABCImage("Header_ID_" + str(header))
        headerImage.setExtraField(bytearray((header).to_bytes(1, byteorder='little')), "Test")
        if(not headerImage.runAll()):
            break;

def testCommentSize(testAllChar = False): # MATCH
    if(VERBOSE):
        print("Test comment size")

    for testCommentSize in range(0, 3000):
        commentImage = ABCImage("Comment_Size_" + str(testCommentSize))
        commentImage.setComment("a" * testCommentSize)
        if(not commentImage.runAll()):
            break;

    if(VERBOSE):
        print("Test special char in comment")

    for decimalValue in [28197, 29952]:
        authorImage = ABCImage("Comment_Character_" + str(decimalValue))
        authorImage.setManualComment(bytearray((decimalValue).to_bytes(2, byteorder='little')))
        if(not authorImage.runAll()):
            break;

    if(testAllChar):
        if(VERBOSE):
            print("Test all char in comment")

        for commentId in range(0, 65535):  # 65535 = ffff
            authorImage = ABCImage("Comment_Character_" + str(commentId))
            authorImage.setManualComment(bytearray((commentId).to_bytes(2, byteorder='little')))
            if(not authorImage.runAll()):
                break;

def testAuthors(testAllChar = False): # MATCH
    if(VERBOSE):
        print("Test size of author name")

    for testAuthorSize in range(0, 200):
        authorImage = ABCImage("Author_Size_" + str(testAuthorSize))
        authorImage.setAuthor("a" * testAuthorSize)
        if(not authorImage.runAll()):
            break;

    if(VERBOSE):
        print("Test special char in author name")

    for decimalValue in [28197, 29952]:
        authorImage = ABCImage("Author_Character_" + str(decimalValue))
        authorImage.setManualAuthor(bytearray((decimalValue).to_bytes(2, byteorder='little')))
        if(not authorImage.runAll()):
            break;

    if(testAllChar):
        if(VERBOSE):
            print("Test all char in author name")

        for authorId in range(0, 65535):  # 65535 = ffff
            authorImage = ABCImage("Author_Character_" + str(authorId))
            authorImage.setManualAuthor(bytearray((authorId).to_bytes(2, byteorder='little')))
            if(not authorImage.runAll()):
                break;

def testNumberOfColor():
    if(VERBOSE):
        print("Test different color number")

    for testColorSize in range(0, 300):
        colorSizeImage = ABCImage("Number_of_Color_" + str(testColorSize))
        colorSizeImage.setNumberOfColor(testColorSize)
        if(not colorSizeImage.runAll()):
            break;

    if(VERBOSE):
        print("Test particular color number")

    for numberColor in ["00000000", "0000000f", "000000f0", "00000f00", "0000f000", "000f0000", 
            "00f00000", "0f000000", "f0000000", "ffffffff"]:
        numberColorImage = ABCImage("Number_of_Color_" + str(numberColor))
        numberColorImage.setManualNumberOfColor(bytearray.fromhex(numberColor))
        if(not numberColorImage.runAll()):
            break;

def testTableColor(): # MATCH
    if(VERBOSE):
        print("Test second color of table color")

    for colorId in range(0, 65535):  # 65535 = ffff
        colorImage = ABCImage("Color_Value_" + str(colorId))
        colorImage.setNumberOfColor(1)
        colorImage.setManualColorTable([bytearray.fromhex("ffffffff"), bytearray((colorId).to_bytes(4, byteorder='little'))])
        if(not colorImage.runAll()):
            break

def testWidth():
    if(VERBOSE):
        print("Test particular width size")

    for width in ["ffffffff", "fffffffe", "00000000", "00ffffff", "ffffff00"]:
        widthImage = ABCImage("Width_" + str(width))
        widthImage.setManualWidth(bytearray.fromhex(width))
        if(not widthImage.runAll()):
            break;

def testHeight(): # MATCH
    if(VERBOSE):
        print("Test particular height size")

    for height in ["ffffffff", "fffffffe", "00000000", "00ffffff", "ffffff00"]:
        heightImage = ABCImage("Height_" + str(height))
        heightImage.setManualHeight(bytearray.fromhex(height))
        if(not heightImage.runAll()):
            break;

def testFakeSize():
    if(VERBOSE):
        print("Test fake size and data")

    for width, height in [[3, 3], [3, 2], [3, 1], [6, 1], [1, 7], [1, 0]]:
        pixelDimensionImage = ABCImage("Six_Pixel_With_Size_" + str(width) + "x" + str(height))
        pixelDimensionImage.setDimension(width, height)
        pixelDimensionImage.setPixel(["00", "01", "01", "00", "01", "00"])  # 6 = 3x2 OR 2x3 OR 1x6 OR 6x1
        if(not pixelDimensionImage.runAll()):
            break;


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fuzzer for ABC Image')

    parser.add_argument("-v", "--verbose", help="Display all conversion message", action="store_true")
    parser.add_argument("-p", "--path", help="Path to the convert file")
    parser.add_argument("-a", "--all", help="Execute all posibility for special character " + \
        "(author and comment field)", action="store_true")

    args = parser.parse_args()

    if(args.verbose):
        VERBOSE = True

    # Specify path to the converter
    pathIsCorrect = True
    if(args.path):
        if(not os.path.isfile(args.path)):
            print("The path to the converter is not valid")
            pathIsCorrect = False
        else:
            DEFAULT_CONVERT_PATH = args.path
    else:
        if(not os.path.isfile(DEFAULT_CONVERT_PATH)):
            print("Warning: " + str(DEFAULT_CONVERT_PATH) + " not found")
            print("Try with " + str(DEFAULT_CONVERT_PATH_IF_FAIL))

            if(os.path.isfile(DEFAULT_CONVERT_PATH_IF_FAIL)):
                DEFAULT_CONVERT_PATH = DEFAULT_CONVERT_PATH_IF_FAIL
            else:
                pathIsCorrect = False
                print("Unable to find converter tool")

    # Execute all images
    if(pathIsCorrect):
        createNormalImage()
        testVersion()
        testHeader()
        testCommentSize(args.all)
        testAuthors(args.all)
        testNumberOfColor()
        testTableColor()
        testWidth()
        testHeight()
        testFakeSize()

