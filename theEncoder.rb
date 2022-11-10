#!/usr/bin/env ruby
require 'base64'
require 'uri'
require 'base16'
require 'ctf_party'

def banner()
	print %q'
							github.com/NioZow
	'.yellow
	puts %q'
  __   .__                                                  .___                
_/  |_ |  |__    ____     ____    ____    ____    ____    __| _/  ____  _______ 
\   __\|  |  \ _/ __ \  _/ __ \  /    \ _/ ___\  /  _ \  / __ | _/ __ \ \_  __ \
 |  |  |   Y  \\  ___/  \  ___/ |   |  \\  \___ (  <_> )/ /_/ | \  ___/  |  | \/
 |__|  |___|  / \___  >  \___  >|___|  / \___  > \____/ \____ |  \___  > |__|   
            \/      \/       \/      \/      \/              \/      \/          
	'.red
	puts "Version 1.0\n".yellow
end

class String
  def red; colorize(self, "\e[1m\e[31m"); end
  def green; colorize(self, "\e[1m\e[32m"); end
  def dark_green; colorize(self, "\e[32m"); end
  def yellow; colorize(self, "\e[1m\e[33m"); end
  def blue; colorize(self, "\e[1m\e[34m"); end
  def dark_blue; colorize(self, "\e[34m"); end
  def purple; colorize(self, "\e[35m"); end
  def dark_purple; colorize(self, "\e[1;35m"); end
  def cyan; colorize(self, "\e[1;36m"); end
  def dark_cyan; colorize(self, "\e[36m"); end
  def pure; colorize(self, "\e[0m\e[28m"); end
  def bold; colorize(self, "\e[1m"); end
  def colorize(text, color_code) "#{color_code}#{text}\e[0m" end
end

def html_decoding(string)
	puts "Simple: ".yellow + string.htmlunescape
	out = ""
	for character in string.split("&#")[1..]
		if character[0] == "x"
			out += (Base16.decode16 character[1..]).to_s
		else
			out += character.ord
		end
	end
	puts "Full: ".yellow + out
end

def html_encoding(string)
	puts "Simple: ".yellow + string.htmlescape
	print "Full #1: ".yellow
	for character in string.chars do print "&#x" + Base16.encode16(character) end
	print "\nFull #2: ".yellow
	for character in string.each_byte do print "&#" + character.to_s end
end

def url_encoding(url)
	return URI(url).to_s
end

def url_decoding(url)
	return URI::Parser.new.unescape url
end

def base64_encoding(string)
	return Base64.encode64 string
end

def base64_decoding(string)
	return Base64.decode64 string
end

def hex_encoding(string)
	return Base16.encode16 string
end

def hex_decoding(string)
	return Base16.decode16 string
end

def main()
	args = ARGV

	banner

	if args.length != 2
		puts "The number of arguments is not correct!".red
	else
		case args[0]
			when "html_encoding"then html_encoding(args[1])
			when "html_decoding" then html_decoding(args[1])
			when "base64_encoding" then puts base64_encoding(args[1])
			when "base64_decoding" then puts base64_decoding(args[1])
			when "url_encoding" then puts url_encoding(args[1])
			when "url_decoding" then puts url_decoding(args[1])
			when "hex_encoding" then puts hex_encoding(args[1])
			when "hex_decoding" then puts hex_decoding(args[1])
			else puts "This type of encoding isn't supported!".red
		end
	end
end

main