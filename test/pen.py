#!/usr/bin/python
import dbus
import argparse

parser = argparse.ArgumentParser(description="USI socket tool")
parser.add_argument('-g', '--get', action="store_true")
parser.add_argument('-i', '--introspect', action="store_true")
parser.add_argument('-c', '--color', type=int, nargs="?", const=1)
parser.add_argument('-w', '--width', type=int, nargs="?", const=1)
parser.add_argument('-s', '--style', type=int, nargs="?", const=1)
parser.add_argument('-u', '--custom', nargs="+")
parser.add_argument('-n', '--index', type=int)
parser.add_argument('-a', '--addr', type=str, nargs=1)
parser.add_argument('-o', '--obj', type=str, nargs=1)
parser.add_argument('-d', '--dump', action="store_true")
parser.add_argument('-v', '--version', action="store_true")

args = parser.parse_args()

#print(args)

name = None

if args.addr == None or args.obj == None:
    args.addr = "org.universalstylus.PenServer"
    args.obj = "/org/universalstylus/Pen"

if args.color != None:
    value = args.color
    name = "LineColor"

if args.width != None:
    value = args.width
    name = "LineWidth"

if args.style != None:
    value = args.style
    name = "LineStyle"

if args.custom != None:
    name = args.custom[0]
    if len(args.custom) > 1:
        value = args.custom[1]

#print(args.addr)
#print(args.obj)

obj = dbus.SystemBus().get_object(args.addr, args.obj)

if args.version != False:
    name = "Version"
    args.get = True

if args.introspect != False:
    print(obj.Introspect())
    quit()

if args.dump != False:
    d = obj.GetAll()
    for key in d:
        val = d[key]
        print("%s:\t%s" % (key, val))
    quit()

if name == None:
    parser.print_help()
    quit()

if args.get == True:
    val = obj.Get("org.universalstylus.PenInterface", name)
    print("%s = %s" % (name, val))
else:
    obj.Set(name, dbus.UInt32(value))
