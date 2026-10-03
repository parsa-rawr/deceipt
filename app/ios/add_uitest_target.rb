#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Adds the DeceiptAppUITests UI-test target to DeceiptApp.xcodeproj.
# A UI-test target needs many interdependent pbxproj objects (native target,
# product, sources phase, build configurations, a target dependency on the app)
# and hand-editing that is error-prone, so this uses the CocoaPods-vendored
# `xcodeproj` gem. It is idempotent: running it twice does not duplicate the
# target.
#
# Usage:  ruby ios/add_uitest_target.rb

# Make the vendored xcodeproj gem loadable.
gems_dir = File.expand_path('../vendor/bundle/ruby/2.6.0/gems', __dir__)
Dir.glob(File.join(gems_dir, '*', 'lib')).each { |d| $LOAD_PATH.unshift(d) unless $LOAD_PATH.include?(d) }
require 'xcodeproj'

project_path = File.expand_path('DeceiptApp.xcodeproj', __dir__)
project = Xcodeproj::Project.open(project_path)

app_target = project.targets.find { |t| t.name == 'DeceiptApp' }
abort('DeceiptApp target not found') unless app_target

ui_target = project.targets.find { |t| t.name == 'DeceiptAppUITests' }
if ui_target
  puts 'DeceiptAppUITests already exists; refreshing sources.'
else
  ui_target = project.new_target(:ui_test_bundle, 'DeceiptAppUITests', :ios, '15.1', nil, :swift)
  puts 'Created DeceiptAppUITests target.'
end

# Sources group + file membership.
group = project.main_group['DeceiptAppUITests'] || project.main_group.new_group('DeceiptAppUITests', 'DeceiptAppUITests')
test_file = 'DeceiptAppUITests/DeceiptUITests.swift'
already = group.files.any? { |f| f.path == 'DeceiptUITests.swift' }
unless already
  file_ref = group.new_reference('DeceiptUITests.swift')
  ui_target.add_file_references([file_ref])
  puts "Added #{test_file} to DeceiptAppUITests."
end

# Build settings: TEST_TARGET_NAME ties the UI tests to the app, and automatic
# signing matches the app target so `-allowProvisioningUpdates` works.
ui_target.build_configurations.each do |config|
  config.build_settings['TEST_TARGET_NAME'] = 'DeceiptApp'
  config.build_settings['PRODUCT_NAME'] = '$(TARGET_NAME)'
  config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'com.deceipt.poc.uitests'
  config.build_settings['CODE_SIGN_STYLE'] = 'Automatic'
  config.build_settings['SWIFT_VERSION'] = '5.0'
  config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.1'
  config.build_settings['GENERATE_INFOPLIST_FILE'] = 'YES'
  config.build_settings['TARGETED_DEVICE_FAMILY'] = '1,2'
end

# Depend on the app target so the app is installed alongside the tests.
unless ui_target.dependencies.any? { |d| d.target == app_target }
  ui_target.add_dependency(app_target)
  puts 'Added dependency on DeceiptApp.'
end

project.save
puts 'Saved project.'
