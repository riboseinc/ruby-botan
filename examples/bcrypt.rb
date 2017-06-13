# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'botan'

print 'Enter a new password: '
phash = Botan::BCrypt.hash(gets.chomp, work_factor: 10)

# some time later...
print 'Enter password: '
if Botan::BCrypt.valid?(password: gets.chomp, phash: phash)
  puts 'Correct password'
else
  puts 'Incorrect password'
end

