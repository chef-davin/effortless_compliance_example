#
# Cookbook:: effortless_compliance
# Recipe:: default
#
# Copyright:: 2021, The Authors, All Rights Reserved.

if linux?
  include_profile 'effortless_compliance::linux_base'
elsif windows?
  include_profile 'effortless_compliance::windows_base'
end
