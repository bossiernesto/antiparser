import cPickle
import sys
import struct
import random
import string
import os
import socket
import time

"""antiparser - API for randomly generating different types of data for use in fuzzing.

The anitparser is a general API that is intended to be used to generically generate
malformed, random data to be used when fuzzing network protocols and file formats.
antiparser is implemented as an object container that is instantiated in an empty
state.  Different types of data objects are then appended to the antiparser container.
Each of these objects has various fields and properties that are appropriate for the
data that they are intended to represent.  antiparser provides methods to randomly
mutate or "permute" each of the objects in the container.  antiparser supports various
modes to determine how the data should be "permuted", including a "random" mode and
a more deterministic "incremental" mode that makes each random permutation incrementally
larger.  The random data is then stored in a "payload" and is available to be used in
Python scripts that implement the fuzzer logic.  The fuzzer logic would typically
entail writing the payload to a network socket or a file, depending on the nature
of the fuzzer.  antiparser also provides methods to save or load permutations of the
data it contains using Python object pickling.  Persistence of antiparser permutations
makes it easy to keep track of particular permutations of antiparser data, which can
be recalled at any time.
"""
 
class antiparser:
  """Main class - should be imported into fuzzer scripts."""
  def __init__(self):
    """Constructor that is called when the class is instantiated."""
    self.objectList = []
    self.payload = ""
    self.modes = ["incremental", "random"]
    self.debug = False # debugging mode - will print various things if True
    self.version = "antiparser-2.0"

  def append(self, item):
    """Append data to the antiparser.

       This method also extracts a new payload from the data set.
    """
    if self.debug:
      print "++ Adding %s to %s ++" % (str(item), str(self))
    self.objectList.append(item)
    self.__extractPayload()

  def delete(self, item):
    """Remove data by name from the antiparser.

       This method also extracts a new payload from the data set.
    """
    if self.debug:
      print "++ Removing %s from %s ++" % (str(item), str(self))
    self.objectList.remove(item)
    self.__extractPayload()

  def display(self):
    """Prints all of the objects in the antiparser."""
    for items in self.getList():
      items.display()

  def load(self, fileName):
    """Loads a file containing a saved antiparser permutation."""
    if self.debug:
      print "++ Atempting to load %s ++" % fileName
    try:
      infile = file(fileName, 'r')
      antiparserobject = cPickle.load(infile)
    except IOError, msg:
      print "antiparser.load() error opening file: "
    except cPickle.UnpicklingError, msg:
      print "antiparser.load() unpickling error: "
    try:
      infile.close()
    except IOError, msg:
      print "antiparser.load() error closing file: "
    if self.debug:
      print "++ Creating antiparser data ++"
    for item in antiparserobject.objectList:
      self.append(item)
    self.__extractPayload()

  def save(self, fileName):
    """Saves the current antiparser permutation to a file."""
    if self.debug:
      print "++ Attempting to save %s to %s ++" % (str(self), fileName)
    (directory, name) = os.path.split(fileName)
    try:
      if os.path.isdir(directory) or directory == "":
        outfile = file(fileName, 'w')
      else:
        os.mkdir(directory, 0700)
        outfile = file(fileName, 'w')
      cPickle.dump(self, outfile, 2)
    except IOError, msg:
      print "antiparser.save() error opening file: "
    except cPickle.PicklingError, msg:
      print "antiparser.save() pickling error: "  
    try:
      outfile.close()
    except IOError, msg:
      print "antiparser.save() error closing file: "
    if self.debug:
      print "++ Saved ++"

  def version(self):
    """Prints the version."""
    print self.version
  
  def getList(self):
    """Return lists of data objects in the current antiparser instance."""
    return self.objectList

  def writeFile(self, fileName):
    """Writes the payload to a file for use in file format fuzzing."""
    if self.debug:
      print "++ Writing payload to %s ++" % fileName
    (directory, name) = os.path.split(fileName)
    try:
      if os.path.isdir(directory) or directory == "":
        outfile = file(fileName, 'w')
        outfile.write(self.getPayload())
      else:
        os.mkdir(directory, 0700)
        outfile = file(fileName, 'w')
        outfile.write(self.getPayload())
    except IOError, msg:
      print "antiparser.writeFile() error opening file: "
    try:
      outfile.close()
    except IOError, msg:
      print "antiparser.writeFile() error closing file: "

  def __extractPayload(self):
    structfmt = ""
    structlist = []
    if self.debug:
      print "++ Extracting new payload from %s ++" % self.getList()
    for item in self.objectList:
      # deal with byte order and optional fields
      if item.getByteOrder() is not None:
        if item.ByteOrder.lower() == "big":
          structfmt += '>'
        if item.ByteOrder.lower() == "little":
          structfmt += '<'
      _inPayload = True # control variable for optional flag
      if item.getOptional():
        choices = True, False,
        _inPayload = random.choice(choices)

      # apCString
      if isinstance(item, apCString):
        if _inPayload:
          terminator = item.getTerminator()
          if terminator is not None:
            length = str(len(item.getContent() + terminator))
          else:
            length = str(len(item.getContent()))
          structfmt += length + 's' + 'x' # append a null
          if terminator is not None:
            structlist.append(str(item.getContent() + terminator))
          else:          
            structlist.append(str(item.getContent()))

      # apString            
      elif isinstance(item, apString):
        if _inPayload:
          terminator = item.getTerminator()
          if terminator is not None:
            length = str(len(item.getContent() + terminator))
          else:
            length = str(len(item.getContent()))
          structfmt += length + 's'
          if terminator is not None:
            structlist.append(str(item.getContent() + terminator))
          else:          
            structlist.append(str(item.getContent()))

      # apKeywords
      elif isinstance(item, apKeywords):
        if _inPayload:
          terminator = item.getTerminator()
          if terminator is not None:
            length = str(len(item.getCurrentKeyword() + item.getSeparator() + item.getContent() + terminator))
          else:
            length = str(len(item.getCurrentKeyword() + item.getSeparator() + item.getContent()))
          structfmt += length + 's'
          if terminator is not None:
            structlist.append(str(item.getCurrentKeyword() + item.getSeparator() + item.getContent() + terminator))
          else:          
            structlist.append(str(item.getCurrentKeyword() + item.getSeparator() + item.getContent()))

      #apChar
      elif isinstance(item, apChar):
        if _inPayload:
          if item.getSigned():
            structfmt += 'b'
          else:
            structfmt += 'B'
          structlist.append(int(item.getContent()))

      # apShort 
      elif isinstance(item, apShort):
        if _inPayload:
          if item.getSigned():
            structfmt += 'h'
          else:
            structfmt += 'H'
          structlist.append(int(item.getContent()))
 
      # apLong
      elif isinstance(item, apLong):
        if _inPayload:
          if item.getSigned():
            structfmt += 'l'
          else:
            structfmt += 'L'
          structlist.append(long(item.getContent()))
      
      # pack and set the payload
      payload = struct.pack(structfmt, *structlist)
      self.__setPayload(payload)

  def getPayload(self):
    """Returns the payload of the current permutation.

       The payload is the random output to be used in fuzzer scripts.
    """
    return self.payload

  def __setPayload(self, payload):
    self.payload = payload

  def displayModes(self):
    """Display a list of supported modes for antiparser.permute()."""
    print "The following modes are available:"
    for item in self.modes:
      print item

  def getDebug(self):
    """Returns the debugging status."""
    return self.debug

  def setDebug(self, debug):
    """Sets the debugging status to True or False.  Defaults to False.

       setDebug() sets the debugging status for the antiparser container only.
       For global debugging of all data objects in the container, use setGlobalDebug().
    """ 
    self.debug = debug

  def getGlobalDebug(self):
    """Returns the global debugging status."""

  def setGlobalDebug(self, debug):
    """Sets the debugging status to True or False for all data objects in the antiparser.  Defaults to False.

       setGlobalDebug() will set the debug status for all of the data objects that have been appended to the
       current antiparser instance.
    """
    if debug is True:
      for item in self.objectList:
        item.setDebug(True)
    if debug is False:
      for item in self.objectList:
        item.setDebug(False)
    self.setDebug(debug)

  def juggle(self):
    """Randomly rearrange the ordering of data objects in the antiparser instance.

       This method extracts the payload of the altered antiparser data.  juggle()
       does not permute the data, just randomly reorders it.  Users can then permit
       the data if they wish.
    """
    random.shuffle(self.objectList)
    if self.debug:
      print "++ Juggling contents of %s ++" % (str(self))
      print self.getList()
    self.__extractPayload()

  def permute(self):
    """Creates a random permutation of the content for each data object in the antiparser."""
    for item in self.objectList:
      if item.getStatic() is False:
        # check the mode
        if item.getMode().lower() == "random":
          # should match all string types
          if self.debug:
            print "++ Permuting %s in random mode ++" % str(item) 
          if isinstance(item, apString):
            tempList = [] # list to build string
            randomString = "" 
            size = 0
            if item.getMinSize() == item.getMaxSize():
              size = item.getMinSize()
            else:
              size = random.randrange(item.getMinSize(), item.getMaxSize())
            for i in xrange(size):
              tempList.append(random.choice(item.charRange))
            randomString = string.join(tempList, '')
            item.setContent(randomString)
          elif (isinstance(item, apChar) or isinstance(item, apShort) or isinstance(item, apLong)):
            number = 0
            if item.getMinSize() == item.getMaxSize():
              number = item.getMinSize()
            else:
              number = random.randrange(item.getMinSize(), item.getMaxSize())
            item.setContent(number)
          elif isinstance(item, apKeywords):
            tempList = [] # list to build string
            randomString = ""
            randomKey = str(random.choice(item.keywords))
            size = ""
            if item.getMinSize() == item.getMaxSize():
              size = item.getMinSize()
            else:
              size = random.randrange(item.getMinSize(), item.getMaxSize())
            for i in xrange(size - 1):
              tempList.append(random.choice(item.charRange))
            item.setCurrentKeyword(randomKey)
            randomString = string.join(tempList, '')
            item.setContent(randomString)

        # crap incremental mode -- not implemented for apChar/apShort/apLong
        if item.getMode().lower() == "incremental":
          if self.debug:
            print "++ Permuting %s in incremental mode ++" % str(item) 
          if isinstance(item, apString) or isinstance(item, apKeywords):
            # this algorithm really sucks but seems to work
            tempList = []
            randomString = ""         
            boundsRange = [16, 32, 128, 256, 512, 1024, 2048,
                           4096, 8192, 16384, 32768, 65536]
            boundsList = []
            delta = 4
            size = 0
            currentSize = item.getContentSize()
            lower = item.getMinSize()
            upper = item.getMaxSize()

            # don't wanna exceed maxsize + delta
            if currentSize > upper + delta:
              currentSize = upper + delta
            # build lower + delta range 
            boundsList.extend(range(lower, lower + delta + 1))  
            # build rest of range
            for number in boundsRange:
              if number not in boundsList:
                if number > lower and number < upper:
                  boundsList.extend(range(number, number + delta + 1))
            # build upper + delta range
            for number in range(upper, upper + delta + 1):
              if number not in boundsList:
                boundsList.append(number)
            listiter = iter(boundsList)
            
            # avoid index+1 error using iterator
            for number in listiter:
              if currentSize < lower:
                size = lower
                break 
              if currentSize == number:
                try:
                  size = listiter.next()
                except StopIteration:
                    size = boundsList[-1]
                break            
            if isinstance(item, apKeywords):
              randomKey = str(random.choice(item.keywords))
              item.setCurrentKeyword(randomKey)
             
            for i in xrange(size):
              tempList.append(random.choice(item.charRange))
            randomString = string.join(tempList, '')
            item.setContent(randomString)
            if self.debug:
              print "Content Length: %s " % item.getContentSize()

      # set the new payload based on changed content
      self.__extractPayload()

class apObject:
  """Parent antiparser data object class -- not be invoked directly."""
  def __init__(self):
    """Constructor that is called when the class is instantiated."""
    # set defaults
    self.minsize = 1
    self.maxsize = 1024
    self.optional = False
    self.static = False
    self.content = ""
    self.byteorder = None
    self.mode = "random"
    self.debug = False

  def display(self):
    """Print the data object."""
    print "Data Object: %s" % str(self)
    stringrep = str(self.__dict__.items()) 
    print stringrep + "\n"

  def getContent(self):
    """Returns the content of the data object."""
    return self.content

  def setContent(self, content):
    """Sets the content of the data object."""
    self.content = content

  def getMinSize(self):
    """Returns the minsize property of the data object."""
    return self.minsize

  def setMinSize(self, minsize):
    """Sets the minsize property of the data object to an integer."""
    if self.debug:
      print "++ Setting minsize for %s to: %s ++" % (str(self), minsize)
    self.minsize = minsize

  def getMaxSize(self):
    """Gets the maxsize property of the data object."""
    return self.maxsize

  def setMaxSize(self, maxsize):
    """Sets the maxsize property of the data object to an integer."""
    if self.debug:
      print "++ Setting maxsize for %s to: %s ++" % (str(self), maxsize)
    self.maxsize =  maxsize

  def getOptional(self):
    """Return the optional property value of the data object."""
    return self.optional

  def setOptional(self, optional):
    """Sets the optional property of the data object to True or False.

       optional is a property that determines whether or not the content should
       be included in the antiparser in any given permutation.  If optional is
       set to True, then there is a 50% chance in any given permutation that the
       content of the data object will be included in the antiparser payload.
       optional defaults to False, which means always include the content of the
       data object in the antiparser payload.
    """
    if self.debug:
      print "++ Setting optional attribute for %s to: %s ++" % (str(self), optional)
    self.optional = optional

  def getStatic(self):
    """Returns the static property value of the data object."""
    return self.static

  def setStatic(self, static):
    """Sets the static property of the data object to True or False.

       static is a property that determines whether or not the content should
       be randomly permuted by the antiparser.  This allows for inclusion of
       static data in the antiparser.  If this value is set to True, then the
       content will not be randomly permuted.  static defaults to False, as 
       the desired default behavior is to randomly permute the content of
       the data object.
    """
    if self.debug:
      print "++ Setting static attribute for %s to: %s ++" % (str(self), static)
    self.static = static

  def getByteOrder(self):
    """Returns the byteorder property of the data object."""
    return self.byteorder

  def setByteOrder(self, byteorder):
    """Sets the byteorder property of the data object to "big" or "little" endian.

       byteorder determines the endianness of the data object.  Valid values
       for byteorder are "big", "little", and None.  byteorder defaults to None, 
       which generally means that the native byteorder is used.
    """
    if self.debug:
      print "++ Setting byteorder attribute for %s to: %s ++" % (str(self), byteorder)
    self.byteorder = byteorder

  def getMode(self):
    """Returns the mode that is currently enabled for the data object."""
    return self.mode
  
  def setMode(self, mode):
    """Sets the mode for the data object.

       mode represents various methods of permuting the data object.  The user
       may wish to generate random objects of random size, within the bounds
       of the minsize and maxsize attributes.  This is the default mode.  Other
       modes may allow the user to generate data of incrementally larger sizes.
    """
    if self.debug:
      print "++ Setting mode for %s to: %s" % (str(self), mode)
    self.mode = mode
  def getDebug(self):
    """Returns the debugging status of the data object."""
    return self.debug

  def setDebug(self, debug):
    """Sets the debugging status to True or False.  Defaults to False."""
    self.debug = debug

class apString(apObject):
  """apString represents a freeform string."""
  def __init__(self):
    apObject.__init__(self)
    self.illegalchars = ""
    self.charRange = []
    self.terminator = None
    self.__extractCharRange()

  def __extractCharRange(self):
    charTable = ""
    tempRange = ""                 
    charTable = string.maketrans('', '')
    self.charRange = list(string.translate(charTable, charTable, self.illegalchars))

  def getIllegalChars(self):
    """Returns a list of illegal characters."""
    return self.illegalchars

  def setIllegalChars(self, chars):
    """Sets a string of illegal characters.

       illegalchars alsos the user to specify characters that will not be included in the
       antiparser payload for the data object.  illegalchars is a string value, and defaults
       to an empty string.  Calling this method changes the range of legal characters, ie:
       the charRange field.
    """
    if self.debug:
      print "++ Setting illegal character range for %s to: %s ++" % (str(self), chars)
    self.illegalchars = chars
    self.__extractCharRange()

  def getTerminator(self):
    """Returns a terminator string."""
    return self.terminator

  def setTerminator(self, terminator):
    """Sets a terminator string for the data object.
  
       terminator is a static string of characters that will be appended to the end of the data object
       content.  This is useful for protocols where each field is terminated, such as fields in an
       HTTP header.  terminator defaults to None, indicating that no terminator is to be used for the
       data object.
    """
    if self.debug:
      print "++ Setting terminator characters for %s to: %s ++" % (str(self), terminator)
    self.terminator = terminator

  def getContentSize(self):
    """Returns the length of the current content."""
    return len(self.content)

class apCString(apString):
  """apCString represents a C style string, ie: an array of chars appended by a null.

     apCString inherits all of its methods from the apString class.  The only difference is
     that apCString object content is terminated with a null character in the antiparser
     payload.
  """ 
  def __init__(self):
    apString.__init__(self)

class apKeywords(apObject):
  """apKeywords represents a list of random values to prepend to the content of the data object.

     The main application of apKeywords is to provide a list of commands or strings to randomly
     cycle through when fuzzing.  apKeywords can be adapted to represent semi-static data where
     the initial part of the data has a limited set of values but the rest of the data is random.
  """ 
  def __init__(self):
    apObject.__init__(self)
    self.keywords = [] # keywords is a list
    self.currentkeyword = ""
    self.illegalchars = ""
    self.charRange = []
    self.terminator = None
    self.separator = ""
    self.__extractCharRange()

  def __extractCharRange(self):
    charTable = ""
    tempRange = ""                 
    charTable = string.maketrans('', '')
    self.charRange = list(string.translate(charTable, charTable, self.illegalchars))

  def getIllegalChars(self):
    """Returns a list of illegal characters."""
    return self.illegalchars

  def setIllegalChars(self, chars):
    """Sets a string of illegal characters.

       illegalchars alsos the user to specify characters that will not be included in the
       antiparser payload for the data object.  illegalchars is a string value, and defaults
       to an empty string.  Calling this method changes the range of legal characters, ie:
       the charRange field.
    """    
    if self.debug:
      print "++ Setting illegal character range for %s to: %s ++" % (str(self), chars) 
    self.illegalchars = chars
    self.__extractCharRange()
    
  def getTerminator(self):
    """Returns a terminator string."""
    return self.terminator

  def setTerminator(self, terminator):
    """Sets a terminator string for the data object.
  
       terminator is a static string of characters that will be appended to the end of the data object
       content.  This is useful for protocols where each field is terminated, such as fields in an
       HTTP header.  terminator defaults to None, indicating that no terminator is to be used for the
       data object.
    """
    if self.debug:
      print "++ Setting terminator characters for %s to: %s ++" % (str(self), terminator)
    self.terminator = terminator
  def getSeparator(self):
    """Returns the separator string for the keywords."""
    return self.separator

  def setSeparator(self, separator):
    """Sets a separator string for the data object.

       separator is a static string of characters that will be appended to the keyword before the beginning
       of the content.  This is useful if certain characters are needed separate a keyword from its arguments.
       separator defaults to an empty string, indicating that no separator will be added between the keyword
       and the content.
    """
    if self.debug:
      print "+++ Setting separator for %s to: %s +++" % (str(self) + separator)
    self.separator = separator

  def getKeywords(self):
    """Returns the list of keywords associated with the data object."""
    return self.keywords
  
  def setKeywords(self, keywords):
    """Sets the list of keywords for the data object.

       keywords represents a list of values.  The antiparser will choose a random value from
       this list for every permutation.  The antiparser will then append the random content
       to the keyword.  The default value is an empty list.  This will also set the current
       keyword associated with the data object to the first keyword in the list.
    """
    if self.debug:
      print "++ Setting keyword list for %s to: %s ++" % (str(self), keywords)
    self.keywords = keywords
    self.setCurrentKeyword(self.keywords[0])
    if self.debug:
      print "++ Setting initial keyword value to: %s ++" % self.getCurrentKeyword()

  def getCurrentKeyword(self):
    """Returns the current keyword associated with the data object."""
    return self.currentkeyword

  def setCurrentKeyword(self, keyword):
    """Sets the current keyword associated with the data object."""
    self.currentkeyword = keyword
  
  def getContentSize(self):
    """Returns the length of the current content."""
    return len(self.content)

class apChar(apObject):
  """apChar represents the char 8-bit C data type."""
  def __init__(self):
    apObject.__init__(self)
    self.content = 0
    # default to unsigned
    self.signed = False
    self.minsize = 0
    self.maxsize =  2**8-1

  def getSigned(self):
    """Returns the value of the signed field for the data object."""
    return self.signed

  def setSigned(self, signed):
    """Sets the value of the signed field for the data object.

    signed defaults to unsigned, which is represented by an argument of False.  If signed is set to
    True, the minsize and maxsize attributes are adjusted to the minimum and maximum value for the
    signed data type.  Therefore, if these properties need to be changed, this should be done after
    setting the signed field.
    """
    if self.debug:
      print "+++ Setting signed value for %s to: %s" % (str(self), signed)
    self.signed = signed

    if self.signed:
      self.setMinSize(-2**7)
      self.setMaxSize(2**7-1)
    else:
      self.setMinSize(0)
      self.setMaxSize(2**8)

class apShort(apObject):
  """apShort represents the short 16-bit C data type."""
  def __init__(self):
    apObject.__init__(self)
    self.content = 0
    # default to unsigned
    self.signed = False
    self.minsize = 0
    self.maxsize = 2**16-1

  def getSigned(self):
    """Returns the value of the signed field for the data object."""
    return self.signed

  def setSigned(self, signed):
    """Sets the value of the signed field for the data object.

    signed defaults to unsigned, which is represented by an argument of False.  If signed is set to
    True, the minsize and maxsize attributes are adjusted to the minimum and maximum value for the
    signed data type.  Therefore, if these properties need to be changed, this should be done after
    setting the signed field.
    """
    if self.debug:
      print "+++ Setting signed value for %s to: %s" % (str(self), signed)
    self.signed = signed
    if self.signed:
      self.setMinSize(-2**15)
      self.setMaxSize(2**15-1)
    else:
      self.setMinSize(0)
      self.setMaxsize(2**16)

class apLong(apObject):
  """apLong represents the short 32-bit C data type."""
  def __init__(self):
    apObject.__init__(self)
    self.content = 0L
    # default to unsigned
    self.signed = False
    self.minsize = 0
    self.maxsize = 2**32-1

  def getSigned(self):
    """Returns the value of the signed field for the data object.""" 
    return self.signed

  def setSigned(self, signed):
    """Sets the value of the signed field for the data object.

    signed defaults to unsigned, which is represented by an argument of False.  If signed is set to
    True, the minsize and maxsize attributes are adjusted to the minimum and maximum value for the
    signed data type.  Therefore, if these properties need to be changed, this should be done after
    setting the signed field.
    """
    if self.debug:
      print "+++ Setting signed value for %s to: %s" % (str(self), signed)
    self.signed = signed
    if self.signed:
      self.setMinSize(-2**31)
      self.setMaxSize(2**31-1)
    else:
      self.setMinSize(0)
      self.setMaxSize(2**32-1)

class apSocket:
  """apSocket is a wrapper class for the Python socket API, for specialized use with the antiparser.
     
     apSocket provides much of the same functionality of the Python socket API, but is implemented as
     a series of shortcuts for using the sockets interface.  When apSocket is instantiated, it implicitly
     creates a socket of the specified type. 
  """

  def __init__(self, type='tcp'):
    """Initializes a socket of the specified type, either 'udp' or 'tcp'.

       __init__ will create a socket which persists until closed using the close().  If no type argument is
       specified, than the default type is 'tcp'.
    """
    self.type = type
    if self.type == 'udp':
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  def connect(self, host, port):
    """Alias for the socket.connect method, forming a TCP connection to host/port.

       This method is called prior to sendTCP, but not sendUDP, since UDP is a connectionless protocol.
    """  
    self.host = host
    self.port = port
    try:
      self.sock.connect((self.host, self.port))
    except socket.error, msg:
      print "Could not connect: ", msg

  def sendTCP(self, payload):
    """Alias for the socket.sendall method, will send the entire payload over the socket."""
    self.sock.sendall(payload)

  def sendUDP(self, payload, host, port):
    """Alias for the socket.sendto method.  

       sendUDP will send packets to host, port until all bytes in payload are sent.
    """
    self.sock.sendto(payload, (host, port))
    
  def recv(self, size):
    """Alias for the socket.recv method, blocks until the number of bytes specified by size is read from the socket."""
    data = self.sock.recv(size)
    return data

  def replayTCP(self, fileName):
    """Sends a permutation of the antiparser that was previously saved over TCP, as specified by fileName.

       replayTCP calls antiparser.load(fileName) internally.  replay also assumes an existing apSocket instance.  The method
       will then send the antiparser permutation to the existing TCP socket.
    """
    ap = antiparser()
    ap.load(fileName)
    self.sendTCP(ap.getPayload())

  def replayUDP(self, fileName, host, port):
    """Sends a permutation of the antiparser that was previously saved over UDP, as specified by fileName.

       replayUDP calls antiparser.load(fileName) internally.  replay also assumes an existing apSocket instance.  The method
       will then send the antiparser permutation to the existing UDP socket.
    """
    ap = antiparser()
    ap.load(fileName)
    self.sendUDP(ap.getPayload(), host, port)

  def sleep(self, secs):
    """Alias for time.sleep, sleeps for the number of seconds specified by the secs argument."""
    time.sleep(secs)

  def close(self):
    """Alias for socket.close method.  This closes the existing socket."""
    self.sock.close()
