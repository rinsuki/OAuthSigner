//
//  File.swift
//  
//
//  Created by user on 2019/09/21.
//

import Foundation

internal extension CharacterSet {
    static var rfc3986: CharacterSet {
        var base = alphanumerics
        base.insert(charactersIn: "-_.~")
        return base
    }
}
