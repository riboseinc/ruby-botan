# frozen_string_literal: true

# (c) 2017 Ribose Inc.

module Botan
  # Versioning scheme: `{botan major}.{botan minor}.{ruby-botan local}`.
  # The major.minor components track the baseline Botan release the gem
  # targets (3.13 = the first release with RFC 8452 AES-GCM-SIV); the
  # patch component is ruby-botan's own iteration counter on top of that
  # baseline. Bump major/minor when the required Botan baseline moves.
  VERSION = '3.13.2'
end # module

