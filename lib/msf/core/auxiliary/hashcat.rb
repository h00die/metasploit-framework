# -*- coding: binary -*-
require 'open3'
require 'fileutils'
#require 'rex/proto/ntlm/crypt'
require 'metasploit/framework/hashcat/cracker'
require 'metasploit/framework/jtr/wordlist' #utilize jtr's wordlist for simplicity


module Msf

###
#
# This module provides methods for working with Hashcat
#
###
module Auxiliary::Hashcat
  include Msf::Auxiliary::Report

  #
  # Initializes an instance of an auxiliary module that calls out to Hashcat
  #

  def initialize(info = {})
    super

    register_options(
      [
        OptPath.new('CUSTOM_WORDLIST',      [false, 'The path to an optional custom wordlist']),
        OptInt.new('ITERATION_TIMOUT',      [false, 'The runtime for each iteration of cracking']),
        #OptPath.new('HASHCAT_PATH'          [false, 'The absolute path to the Hashcat executable']),
        OptBool.new('MUTATE',               [false, 'Apply common mutations to the Wordlist (SLOW)', false]),
        OptPath.new('POT',                  [false, 'The path to a Hashcat/John POT file to use instead of the default']),
        OptBool.new('USE_CREDS',            [false, 'Use existing credential data saved in the database', true]),
        OptBool.new('USE_DB_INFO',          [false, 'Use looted database schema info to seed the wordlist', true]),
        OptBool.new('USE_DEFAULT_WORDLIST', [false, 'Use the default metasploit wordlist', true]),
        OptBool.new('USE_HOSTNAMES',        [false, 'Seed the wordlist with hostnames from the workspace', true]),
        OptBool.new('USE_ROOT_WORDS',       [false, 'Use the Common Root Words Wordlist', true])
      ], Msf::Auxiliary::Hashcat
    )
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    puts("BUGGGG re-enable hashcat_path")
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
  end

  # This method creates a new {Metasploit::Framework::Hashcat::Cracker} and populates
  # some of the attributes based on the module datastore options.
  #
  # @return [nilClass] if there is no active framework db connection
  # @return [Metasploit::Framework::Hashcat::Cracker] if it successfully creates a Hashcat Cracker object
  def new_hashcat_cracker
    return nil unless framework.db.active
    Metasploit::Framework::Hashcat::Cracker.new(
        hashcat_path: datastore['HASHCAT_PATH'],
        max_runtime: datastore['ITERATION_TIMEOUT'],
        pot: datastore['POT'],
        wordlist: datastore['CUSTOM_WORDLIST']
    )
  end

  # This method instantiates a {Metasploit::Framework::JtR::Wordlist}, writes the data
  # out to a file and returns the {Rex::Quickfile} object.  A custom Hashcat dictionary
  # method isn't required, and the JtR one is mirrored here
  #
  # @param max_len [Integer] max length of a word in the wordlist, 0 default for ignored value
  # @return [nilClass] if there is no active framework db connection
  # @return [Rex::Quickfile] if it successfully wrote the wordlist to a file
  def wordlist_file(max_len = 0)
    return nil unless framework.db.active
    wordlist = Metasploit::Framework::JtR::Wordlist.new(
        custom_wordlist: datastore['CUSTOM_WORDLIST'],
        mutate: datastore['MUTATE'],
        use_creds: datastore['USE_CREDS'],
        use_db_info: datastore['USE_DB_INFO'],
        use_default_wordlist: datastore['USE_DEFAULT_WORDLIST'],
        use_hostnames: datastore['USE_HOSTNAMES'],
        use_common_root: datastore['USE_ROOT_WORDS'],
        workspace: myworkspace
    )
    wordlist.to_file(max_len)
  end

  # This method takes a {framework.db.cred}, and normalizes it
  # to the string format hashcat is expecting.
  # https://hashcat.net/wiki/doku.php?id=example_hashes
  #
  # @param [credClass] a credential from framework.db
  # @return [String] the hash in jtr format or nil on no mach
  def hash_to_hashcat(cred)
    case cred.private.type
    when 'Metasploit::Credential::NTLMHash'
      both = cred.private.data.split(":")
      if both[0] == 'AAD3B435B51404EEAAD3B435B51404EE' #lanman empty, return ntlm
        return both[1] # ntlm hash-mode: 1000
      end
      return both[0] #give lanman, hash-mode: 3000
    when 'Metasploit::Credential::PostgresMD5' #hash-mode: 12
      if cred.private.jtr_format =~ /postgres|raw-md5/
        hash_string = cred.private.data
        hash_string.gsub!(/^md5/, '')
        return "#{hash_string}:#{cred.public.username}"
      end
    when 'Metasploit::Credential::NonreplayableHash'
      case cred.private.jtr_format
        # oracle 11+ password hash descriptions:
        # this password is stored as a long ascii string with several sections
        # https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/changes-in-oracle-database-12c-password-hashes/
        # example:
        # hash = []
        # hash << "S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;"
        # hash << "H:DC9894A01797D91D92ECA1DA66242209;"
        # hash << "T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C"
        # puts hash.join('')
        # S: = 60 characters -> sha1(password + salt (10 bytes))
        #         40 char sha1, 20 char salt
        #         hash is 8F2D65FB5547B71C8DA3760F10960428CD307B1C
        #         salt is 6271691FC55C1F56554A
        # H: = 32 characters
        #         legacy MD5
        # T: = 160 characters
        #         PBKDF2-based SHA512 hash specific to 12C (12.1.0.2+)
      when /raw-sha1|oracle11/ # oracle 11, hash-mode: 112
        if cred.private.data =~ /S:([\dA-F]{60})/ # oracle 11
          return $1
        end
      when /oracle12c/
        if cred.private.data =~ /T:([\dA-F]{160})/ # oracle 12c, hash-mode: 12300
          return $1.upcase
        end
      when /dynamic_1506/
        #this may not be correct
        if cred.private.data =~ /H:([\dA-F]{32})/ # oracle 11, hash-mode: 3100
          return "#{$1}:#{cred.public.username}"
        end
      when /oracle/ # oracle
        if cred.private.jtr_format.start_with?('des') # 'des,oracle', not oracle11/12c, hash-mode: 3100
          return "#{cred.public.username}:#{cred.public.username}"
        end
      when /md5/
        #            md5(crypt) 
        # hash-mode: 500
        return cred.private.data.sub('$1$', '')
      when /sha256/, /sha-256/
        #            sha256 
        # hash-mode: 1411
        return cred.private.data.sub('$5$','{SSHA256}')
      when /sha512/, /sha-512/
        #            sha512(crypt) 
        # hash-mode: 1711
        return  cred.private.data.sub('$6$','{SSHA512}')
      when /des|bsdi|crypt|bf/, /mysql/, /mssql/
        #            md5(crypt), des(crypt), b(crypt)
        # hash-mode: 500          1500        3200
        #            mssql, mssql, mysql, mysql-sha1
        # hash-mode: 131,    132,  200        300
        return cred.private.data
      end
    end
    nil
  end

end
end
