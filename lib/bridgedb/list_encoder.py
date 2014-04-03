
from cStringIO import StringIO

# S-expression-like format, with "<" and ">" as list delimiters
#
# bytestrings are prefixed by their length (minimal-length ASCII decimal),
# then a ":", as in bencode and the horrible SPKI canonical S-expression format
#
# no spaces are added within or between objects
#
# examples:
#   "<8:greeting5:hello5:world>"
#   "18:Look, ma! No list!"
#   "<4:list<4:list32:Lists may be nested arbitrarily.>0:>"

class FormatError(Exception):
    "A non-decodable byte sequence was passed to a decode function."
    pass

class DataError(Exception):
    "A non-encodable object was passed to an encode function."
    pass

def encode_length(i):
    if not (isinstance(i, int) or isinstance(i, long)):
        raise DataError('non-integer lengths are not supported')
    if i < 0:
        raise DataError('negative lengths are not possible')
    if i == 0:
        return '0'
    # Python is too object-oriented for me to trust its built-in
    # int-to-string conversion functions to always do the right thing.
    acc = list()
    while i > 0:
        acc.append(chr(ord('0') + (i % 10)))
        i = i // 10
        pass
    return ''.join(reversed(acc))

def encode_stringoid_to_stream(stm, obj):
    stm.write(encode_length(len(obj)))
    stm.write(':')
    stm.write(obj)
    pass

def encode_listoid_to_stream(stm, obj):
    stm.write('<')
    for x in obj:
        encode_to_stream(stm, x)
        pass
    stm.write('>')
    pass

def encode_to_stream(stm, obj):
    if isinstance(obj, basestring):
        encode_stringoid_to_stream(stm, obj)
        pass
    elif isinstance(obj, list) or isinstance(obj, tuple):
        encode_listoid_to_stream(stm, obj)
        pass
    else:
        raise DataError("don't know how to encode object of type %s" %
                        (type(obj)))
    pass

def encode(obj):
    stm = StringIO()
    encode_to_stream(stm, obj)
    return stm.getvalue()

def decode_length(length_chars):
    if len(length_chars) == 0:
        raise FormatError('empty string length not permitted')
    if len(length_chars) > 1:
        if length_chars[0] == '0':
            raise FormatError('unnecessary leading zeros in string length ' +
                              'not permitted')
        pass
    acc = 0
    for ch in length_chars:
        i = ord(ch) - ord('0')
        if i < 0 or i >= 10:
            raise FormatError('non-decimal-digit byte in string length')
        acc *= 10
        acc += i
        pass
    return acc

def decode_stringoid_from_stream(stm, first_byte):
    acc = list()
    ch = first_byte
    while ch != ':':
        acc.append(ch)
        ch = stm.read(1)
        pass
    # ch == ':', acc is a list of characters specifying the string length,
    # and stm is positioned at the beginning of the string's content
    slen = decode_length(acc)
    s = stm.read(slen)
    if len(s) != slen:
        raise FormatError('unexpected EOF in string?')
    return s

def decode_listoid_from_stream(stm, first_byte):
    assert first_byte == '<'
    acc = list()
    ch = stm.read(1)
    while ch != '>' and ch != '':
        acc.append(decode_from_stream_internal(stm, ch))
        ch = stm.read(1)
        pass
    if ch == '':
        raise FormatError('unexpected EOF in list')
    # ch == '>' -- end of list
    return acc

def decode_from_stream_internal(stm, first_byte):
    if first_byte == '<':
        return decode_listoid_from_stream(stm, first_byte)
    elif first_byte in '0123456789':
        return decode_stringoid_from_stream(stm, first_byte)
    elif first_byte == '':
        raise FormatError('unexpected EOF')
    else:
        raise FormatError('unexpected character')
    pass

def decode_from_stream(stm):
    return decode_from_stream_internal(stm, stm.read(1))

def decode(s):
    stm = StringIO(s)
    rv = decode_from_stream(stm)
    if stm.tell() != len(s):
        raise FormatError('junk at end of string')
    return rv

