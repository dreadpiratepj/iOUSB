//
//  main.swift
//  iOUSB
//
//  Created by Brandon on 2018-05-21.
//  Copyright © 2018 XIO. All rights reserved.
//

import Foundation
import UIKit


extension String: Error {}

UIApplicationMain(CommandLine.argc, UnsafeMutableRawPointer(CommandLine.unsafeArgv).bindMemory(to: UnsafeMutablePointer<Int8>.self, capacity: Int(CommandLine.argc)), NSStringFromClass(UIApplication.self), NSStringFromClass(AppDelegate.self))
