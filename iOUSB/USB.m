//
//  USB.m
//  iOUSB
//
//  Created by Brandon on 2018-05-26.
//  Copyright © 2018 XIO. All rights reserved.
//

#import "USB.h"
#import <IOKit/IOKitLib.h>
#import <IOKit/usb/IOUSBLib.h>
#import <IOKit/IOCFPlugIn.h>
#import <IOKit/IOMessage.h>
@import ObjectiveC.runtime;

#define kNintendoSwitchVendorID 0x0955
#define kNintendoSwitchProductID 0x7321

#define USB_REQ_GET_STATUS 0x00
#define USB_DIR_IN 0x80 /* to host */
#define USB_RECIP_ENDPOINT 0x02

#define TIMEOUT 1000 // milliseconds

#define MAX_LENGTH 0x30298 // length of the exploit packet
#define RCM_PAYLOAD_ADDR 0x40010000
#define INTERMEZZO_LOCATION 0x4001F000
#define PAYLOAD_LOAD_BLOCK 0x40020000
#define SEND_CHUNK_SIZE 0x1000

#define INTERMEZZO_PATH "intermezzo.bin"
#define PAYLOAD_PATH "fusee.bin"

struct USBNotification
{
    void* this;
    IONotificationPortRef notificationPort;
    io_iterator_t deviceIterator;
    io_object_t notification;
    CFRunLoopRef runLoop;
    void(*deviceCallback)(id this, SEL sel, NSArray<NSString *> *info);
};

// Implementation
@implementation USB

// Function to retrieve an interface from a plugin..
void** getInterface(io_service_t device, CFUUIDRef type, CFUUIDRef uuid)
{
    // Create a plugin interface for the device.
    IOCFPlugInInterface **plugInInterface = nil;
    SInt32 score = 0;
    
    kern_return_t kr = IOCreatePlugInInterfaceForService(device, type, kIOCFPlugInInterfaceID, &plugInInterface, &score);
    
    if ((kIOReturnSuccess != kr) || !plugInInterface)
    {
        return nil;
    }
    
    // Get a USBDeviceInterface from the plugin.. and release the plugin
    void **deviceInterface = nil;
    HRESULT res = (*plugInInterface)->QueryInterface(plugInInterface, CFUUIDGetUUIDBytes(uuid), (LPVOID*) &deviceInterface);
    (*plugInInterface)->Release(plugInInterface);
    
    if (res || !deviceInterface)
    {
        return nil;
    }
    return deviceInterface;
};

// When a device has been plugged into the phone's serial port, this function will get called..
// However, I've restricted it to just the nintendo switch.. so it will only be called if a nintendo switch is plugged in..
void DeviceAdded(void *userInfo, io_iterator_t iterator)
{
    kern_return_t kr;
    io_service_t usbDevice;
    
    NSMutableArray *strings = [[NSMutableArray alloc] init];
    struct USBNotification *notificationInfo = (struct USBNotification *)userInfo;
    
    //Function to retrieve a USB property..
    int (^getUSBProperty)(io_service_t, NSString *) = ^int(io_service_t device, NSString *propertyName) {
        CFNumberRef number = (CFNumberRef)IORegistryEntryCreateCFProperty(device, (__bridge CFStringRef)(propertyName), kCFAllocatorDefault, 0);
        
        if (number) {
            int value = 0;
            CFNumberGetValue(number, kCFNumberSInt32Type, &value);
            CFRelease(number);
            return value;
        }
        return -1;
    };
    
    //Function to retrieve a USBDevice interface..
    IOUSBDeviceInterface** (^getDeviceInterface)(io_service_t) = ^IOUSBDeviceInterface**(io_service_t device) {
        return (IOUSBDeviceInterface **)getInterface(device, kIOUSBDeviceUserClientTypeID, kIOUSBDeviceInterfaceID);
    };
    
    // Iterate over all devices..
    while ((usbDevice = IOIteratorNext(iterator))) {
        UInt32 locationID;

        io_name_t devName;
        io_name_t className;
        io_string_t pathName;
        io_string_t planeName;
        
        IORegistryEntryGetName(usbDevice, devName);
        IOObjectGetClass(usbDevice, className);
        IORegistryEntryGetPath(usbDevice, kIOServicePlane, pathName);
        IORegistryEntryGetPath(usbDevice, kIOUSBPlane, planeName);
        int vendorId = getUSBProperty(usbDevice, [NSString stringWithUTF8String:kUSBVendorID]);
        int productId = getUSBProperty(usbDevice, [NSString stringWithUTF8String:kUSBProductID]);
        
        [strings addObject:[NSString stringWithFormat:@"Device Name: %s", devName]];
        [strings addObject:[NSString stringWithFormat:@"Device Class: %s", className]];
        [strings addObject:[NSString stringWithFormat:@"Device Plane: %s", planeName]];
        [strings addObject:[NSString stringWithFormat:@"Device Path: %s", pathName]];
        [strings addObject:[NSString stringWithFormat:@"VendorID: 0x%04X", vendorId]];
        [strings addObject:[NSString stringWithFormat:@"ProductID: 0x%04X", productId]];
        
        // Get a USBDeviceInterface from the plugin.. and release the plugin
        WriteToUSB(notificationInfo, usbDevice, strings);
        
        IOUSBDeviceInterface **deviceInterface = getDeviceInterface(usbDevice);
        if (deviceInterface)
        {
            // Get the location ID from the USB Interface
            (*deviceInterface)->GetLocationID(deviceInterface, &locationID);
            [strings addObject:[NSString stringWithFormat:@"LocationID: 0x%x", locationID]];
            
            // Cleanup
            (*deviceInterface)->Release(deviceInterface);
            deviceInterface = nil;
        }
        
        
        // Register for Device Notifications.. IE: Disconnected Notification..
        kr = IOServiceAddInterestNotification(notificationInfo->notificationPort,
                                              usbDevice,
                                              kIOGeneralInterest,
                                              DeviceDisconnected,
                                              notificationInfo,
                                              &notificationInfo->notification
                                              );
        
        [strings addObject:@"\n"];
        // Cleanup
        kr = IOObjectRelease(usbDevice);
    }
    
    void(^deviceCallback)(NSArray<NSString *> *info) = (typeof(deviceCallback))imp_getBlock((IMP)notificationInfo->deviceCallback);
    deviceCallback(strings);
}

// When a device notification has been received, this function is called.
// I'm specifically limiting it to when the switch has disconnected.
void DeviceDisconnected(void *userInfo, io_service_t service, natural_t messageType, void *messageArgument)
{
    struct USBNotification *notificationInfo = (struct USBNotification *)userInfo;
    
    if (messageType == kIOMessageServiceIsTerminated) {
        void(^deviceCallback)(NSArray<NSString *> *info) = (typeof(deviceCallback))imp_getBlock((IMP)notificationInfo->deviceCallback);
        
        deviceCallback(@[@"Device Disconnected"]);
        
        // Cleanup
        IOObjectRelease(notificationInfo->notification);
        free(userInfo);
    }
    else {
        void(^deviceCallback)(NSArray<NSString *> *info) = (typeof(deviceCallback))imp_getBlock((IMP)notificationInfo->deviceCallback);
        deviceCallback(@[@"Message Received"]);
    }
}

struct usb_ctrlrequest {
    UInt8 bRequestType;
    UInt8 bRequest;
    UInt16 wValue;
    UInt16 wIndex;
    UInt16 wLength;
    UInt32 timeout; /* in milliseconds */
    void *data;
};

int control_transfer_unbounded(IOUSBDeviceInterface300** dev, UInt16 length)
{
    int buf_size = sizeof(struct usb_ctrlrequest) + length;
    char *buffer = calloc(1, buf_size);
    
    struct usb_ctrlrequest *ctrl_req = (struct usb_ctrlrequest *) buffer;
    ctrl_req->bRequestType = USB_DIR_IN | USB_RECIP_ENDPOINT;
    ctrl_req->bRequest = USB_REQ_GET_STATUS;
    ctrl_req->wLength = length;
    
    IOUSBDevRequest req;
    req.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    req.bRequest = USB_REQ_GET_STATUS;
    req.wValue = 0;
    req.wIndex = 0;
    req.wLength = buf_size;
    req.pData = buffer;
    req.wLenDone = 0;
    
    IOReturn rc = (*dev)->DeviceRequest(dev, &req);
    
    if(rc != kIOReturnSuccess)
    {
        return -1;
    }
    
    //SMASHED THE STACK!?
    
    return req.wLenDone;
}

int buildAndRunPayload(IOUSBDeviceInterface300** dev, IOUSBInterfaceInterface300** interface)
{
    FILE *intermezzo_file;
    FILE *payload_file;
    char payload_buf[MAX_LENGTH]; // XXX: don't use more memory than we need, ~200k is a lot
    int payload_idx = 0;
    int payload_len;
    
    /* Begin payload construction */
    // TODO: construct the payload on-the-fly as it is sent, saving memory
    memset(payload_buf, 0, sizeof(payload_buf));
    
    *(uint32_t *)payload_buf = MAX_LENGTH;
    payload_idx    = 680; // skip over the header
    
    /* fill the stack with the intermezzo address */
    for (int i=RCM_PAYLOAD_ADDR; i<INTERMEZZO_LOCATION; i += 4, payload_idx += 4)
        *(uint32_t *)&payload_buf[payload_idx] = INTERMEZZO_LOCATION;

    char *bundlePath = [[[NSBundle mainBundle] resourcePath] UTF8String];

    /* load intermezzo.bin */
    if ((intermezzo_file = fopen(strcat(bundlePath, INTERMEZZO_PATH), "r")) == NULL) {
        printf("[-] Failed to open " INTERMEZZO_PATH);
        return -1;
    }
    
    int intermezzo_len = fread(&payload_buf[payload_idx], 1, MAX_LENGTH - payload_idx, intermezzo_file);
    fclose(intermezzo_file);
    printf("[*] Read %d bytes from "INTERMEZZO_PATH"\n", intermezzo_len);
    
    /* pad until payload */
    payload_idx += PAYLOAD_LOAD_BLOCK - INTERMEZZO_LOCATION;
    
    /* load the actual payload */
    if ((payload_file = fopen(strcat(bundlePath, PAYLOAD_PATH), "r")) == NULL) {
        printf("[-] Failed to open payload file");
        return -1;
    }
    
    int file_len = fread(&payload_buf[payload_idx], 1, MAX_LENGTH - payload_idx, payload_file);
    payload_idx += file_len;
    fclose(payload_file);
    printf("[*] Read %d bytes of payload\n", file_len);
    if (payload_idx == MAX_LENGTH)
        printf("[*] Warning: payload may have been truncated. Continuing.");
    
    /* Send the payload */
    payload_len = payload_idx;
    int low_buffer = 1;
    UInt8 pipe_ref = 1;
    for (payload_idx = 0; payload_idx < payload_len || low_buffer; payload_idx += SEND_CHUNK_SIZE, low_buffer ^= 1) {
        if((*interface)->WritePipe(interface, pipe_ref, &payload_buf[payload_idx], SEND_CHUNK_SIZE) != kIOReturnSuccess)
            //if (ep_write(usb_fd, 1, &payload_buf[payload_idx], SEND_CHUNK_SIZE, TIMEOUT) != SEND_CHUNK_SIZE) {
            printf("[-] Sending payload failed");
        return -1;
    }

    printf("[+] Sent 0x%x bytes\n", payload_idx);
    /* Smash the stack! */
    printf("[+] Smashed the stack: %d\n", control_transfer_unbounded(dev, 0x7000));
    return 0;
}

// Test writing to the Nintendo Switch's USB..
void WriteToUSB(struct USBNotification *notificationInfo, io_service_t usbDevice, NSMutableArray* strings)
{
    //Function to retrieve a USBDevice interface..
    IOUSBDeviceInterface300** (^getDeviceInterface)(io_service_t) = ^IOUSBDeviceInterface300**(io_service_t device) {
        return (IOUSBDeviceInterface300 **)getInterface(device, kIOUSBDeviceUserClientTypeID, kIOUSBDeviceInterfaceID300);
    };
    
    //Function to retrieve a USBInterface interface..
    IOUSBInterfaceInterface300** (^getUSBInterface)(io_service_t) = ^IOUSBInterfaceInterface300**(io_service_t device) {
        return (IOUSBInterfaceInterface300 **)getInterface(device, kIOUSBInterfaceUserClientTypeID, kIOUSBInterfaceInterfaceID300);
    };
    // Open the USB device for communication.
    IOUSBDeviceInterface300 **deviceInterface = getDeviceInterface(usbDevice);
    if (deviceInterface)
    {
        if ((*deviceInterface)->USBDeviceOpen(deviceInterface) == kIOReturnSuccess)
        {
            //Get the configuration..
            IOUSBConfigurationDescriptorPtr config;
            kern_return_t kr = (*deviceInterface)->GetConfigurationDescriptorPtr(deviceInterface, 0, &config);
            if (kr == kIOReturnSuccess)
            {
                (*deviceInterface)->SetConfiguration(deviceInterface, config->bConfigurationValue);
                
                //Find the USB interface..
                IOUSBFindInterfaceRequest interfaceRequest;
                interfaceRequest.bInterfaceClass = kIOUSBFindInterfaceDontCare;
                interfaceRequest.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
                interfaceRequest.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
                interfaceRequest.bAlternateSetting = kIOUSBFindInterfaceDontCare;
                
                //Get an interface iterator..
                io_iterator_t iterator;
                kr = (*deviceInterface)->CreateInterfaceIterator(deviceInterface, &interfaceRequest, &iterator);
                if (kr == kIOReturnSuccess)
                {
                    if ((usbDevice = IOIteratorNext(iterator)))
                    {
                        IOUSBInterfaceInterface300 **usbInterface = getUSBInterface(usbDevice);
                        if (usbInterface)
                        {
                            kr = (*usbInterface)->USBInterfaceOpen(usbInterface);
                            if (kr == kIOReturnSuccess) {
                                UInt8 pipe_ref = 1;
                                kr = (*usbInterface)->GetPipeStatus(usbInterface, pipe_ref);
                                switch (kr) {
                                    case kIOReturnNoDevice:
                                        [strings addObject:@"Pipe Status: No Device"];
                                        break;
                                    case kIOReturnNotOpen:
                                        [strings addObject:@"Pipe Status: Not Open"];
                                        break;
                                    case kIOReturnSuccess:
                                        [strings addObject:@"Pipe Status: Open"];
                                        break;
                                    case kIOReturnBusy:
                                        [strings addObject:@"Pipe Status: Busy"];
                                        break;
                                    default:
                                        [strings addObject:@"Pipe Status: We screwed up"];
                                        break;
                                }
                                
                                buildAndRunPayload(deviceInterface, usbInterface);
                            }
                            
                            (*usbInterface)->Release(usbInterface);
                        }
                        
                        IOObjectRelease(usbDevice);
                    }
                    
                    IOObjectRelease(iterator);
                }
            }
            
            (*deviceInterface)->USBDeviceClose(deviceInterface);
        }
        
        (*deviceInterface)->Release(deviceInterface);
    }
}

- (void)addDeviceListener:(void(^)(NSArray<NSString *> *info))listener {
    CFMutableDictionaryRef matchingDict = IOServiceMatching("IOUSBHostDevice");
    if (matchingDict == nil)
    {
        return;
    }
    
    // Add Nintendo Switch
    long usbVendor = kNintendoSwitchVendorID;
    long usbProduct = kNintendoSwitchProductID;
    CFNumberRef numberRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &usbVendor);
    CFDictionarySetValue(matchingDict, CFSTR(kUSBVendorID), numberRef);
    CFRelease(numberRef);

    // Create a CFNumber for the idProduct and set the value in the dictionary
    numberRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &usbProduct);
    CFDictionarySetValue(matchingDict, CFSTR(kUSBProductID), numberRef);
    CFRelease(numberRef);
    numberRef = nil;
    
    // Setup notifications for when the device is available (IE: the switch has been plugged in)
    struct USBNotification *notificationInfo = malloc(sizeof(struct USBNotification));
    notificationInfo->this = (__bridge void *)(self);
    notificationInfo->deviceCallback = (typeof(notificationInfo->deviceCallback))imp_implementationWithBlock(listener);
    notificationInfo->notificationPort = IONotificationPortCreate(kIOMasterPortDefault);
    notificationInfo->runLoop = CFRunLoopGetCurrent();
    notificationInfo->deviceIterator = 0;
    
    CFRunLoopSourceRef runLoopSource = IONotificationPortGetRunLoopSource(notificationInfo->notificationPort);
    CFRunLoopAddSource(notificationInfo->runLoop, runLoopSource, kCFRunLoopDefaultMode);
    
    // Now set up a notification to be called when a device is matched by I/O Kit.
    IOServiceAddMatchingNotification(notificationInfo->notificationPort,
                                     kIOMatchedNotification,
                                     matchingDict,
                                     DeviceAdded,
                                     notificationInfo, //userInfo
                                     &notificationInfo->deviceIterator
                                     );

    // Call for existing devices (in case device is already plugged in)
    DeviceAdded(notificationInfo, notificationInfo->deviceIterator);
}


// Manually called to list all USB device properties for the nintendo switch..
- (NSArray<NSString *> *)getUSBDevices {
    NSMutableArray *strings = [[NSMutableArray alloc] init];
    
    CFMutableDictionaryRef matchingDict;
    io_iterator_t iter;
    kern_return_t kr;
    io_service_t device;
    
    matchingDict = IOServiceMatching("IOUSBHostDevice"); //kIOUSBDeviceClassName for OSX but "IOUSBHostDevice" for iOS..
    if (matchingDict == nil)
    {
        return nil;
    }
    
    //Add Nintendo Switch
    long usbVendor = kNintendoSwitchVendorID;
    long usbProduct = kNintendoSwitchProductID;
    CFNumberRef numberRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &usbVendor);
    CFDictionarySetValue(matchingDict, CFSTR(kUSBVendorID), numberRef);
    CFRelease(numberRef);
    
    // Create a CFNumber for the idProduct and set the value in the dictionary
    numberRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &usbProduct);
    CFDictionarySetValue(matchingDict, CFSTR(kUSBProductID), numberRef);
    CFRelease(numberRef);
    numberRef = nil;
    
    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
    if (kr != KERN_SUCCESS)
    {
        return nil;
    }
    
    // Iterate over all usb devices..
    while ((device = IOIteratorNext(iter)))
    {
        io_name_t devName;
        io_name_t className;
        io_string_t pathName;
        io_string_t planeName;
        
        IORegistryEntryGetName(device, devName);
        IOObjectGetClass(device, className);
        IORegistryEntryGetPath(device, kIOServicePlane, pathName);
        IORegistryEntryGetPath(device, kIOUSBPlane, planeName);
        
        int vendorId = [self getDeviceVendorId:device];
        int productId = [self getDeviceProductId:device];
        NSString *serialNumber = [self getDeviceSerialNumber:device];
        NSString *manufacturer = [self getDeviceManufacturer:device];
        
        [strings addObject:[NSString stringWithFormat:@"Device Name: %s", devName]];
        [strings addObject:[NSString stringWithFormat:@"Device Class: %s", className]];
        [strings addObject:[NSString stringWithFormat:@"Device Plane: %s", pathName]];
        [strings addObject:[NSString stringWithFormat:@"Device Path: %s", planeName]];

        [strings addObject:[NSString stringWithFormat:@"VendorID: %04X", vendorId]];
        [strings addObject:[NSString stringWithFormat:@"ProductID: %04X", productId]];
        [strings addObject:[NSString stringWithFormat:@"Device Serial Number: %@", serialNumber]];
        [strings addObject:[NSString stringWithFormat:@"Device Manufacturer: %@", manufacturer]];

        [strings addObject:@"\n"];
        IOObjectRelease(device);
    }
    
    IOObjectRelease(iter);
    return strings;
}

- (int)getDeviceVendorId:(io_service_t)device {
    return [self getUSBProperty:device propertyName:@"idVendor"];
}

- (int)getDeviceProductId:(io_service_t)device {
    return [self getUSBProperty:device propertyName:@"idProduct"];
}

- (NSString *)getDeviceSerialNumber:(io_service_t)device {
    IOUSBDeviceInterface182 **deviceInterface = [self getDeviceInterface:device];
    if (deviceInterface) {
        UInt8 index;
        (*deviceInterface)->USBGetSerialNumberStringIndex(deviceInterface, &index);
        NSString *result = [self getDeviceStringDescriptor:deviceInterface index:index];
        (*deviceInterface)->Release(deviceInterface);
        return result;
    }
    return nil;
}

- (NSString *)getDeviceManufacturer:(io_service_t)device {
    IOUSBDeviceInterface182 **deviceInterface = [self getDeviceInterface:device];
    if (deviceInterface) {
        UInt8 index;
        (*deviceInterface)->USBGetManufacturerStringIndex(deviceInterface, &index);
        NSString *result = [self getDeviceStringDescriptor:deviceInterface index:index];
        (*deviceInterface)->Release(deviceInterface);
        return result;
    }
    return nil;
}

/// MARK: -

- (int)getUSBProperty:(io_service_t)device propertyName:(NSString *)propertyName {
    CFNumberRef number = (CFNumberRef)IORegistryEntryCreateCFProperty(device, (__bridge CFStringRef)(propertyName), kCFAllocatorDefault, 0);
    
    if (number) {
        int value = 0;
        CFNumberGetValue(number, kCFNumberSInt32Type, &value);
        CFRelease(number);
        return value;
    }
    return -1;
}

- (IOUSBDeviceInterface182 **)getDeviceInterface:(io_service_t)device {
    kern_return_t result;
    SInt32 score;
    IOCFPlugInInterface **plugin = nil;
    result = IOCreatePlugInInterfaceForService(device, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
    if (result != KERN_SUCCESS) {
        return nil;
    }
    
    IOUSBDeviceInterface182 **deviceInterface = nil;
    result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID182), (void **)&deviceInterface);
    if (result != KERN_SUCCESS) {
        IODestroyPlugInInterface(plugin);
        return nil;
    }
    IODestroyPlugInInterface(plugin);
    return deviceInterface;
}

- (NSString *)getDeviceStringDescriptor:(IOUSBDeviceInterface182 **)deviceInterface index:(uint8_t)index {
    UInt8 requestBuffer[256];
    IOUSBDevRequest request = {
        .bmRequestType = USBmakebmRequestType(kUSBIn, kUSBStandard, kUSBDevice),
        .bRequest = kUSBRqGetDescriptor,
        .wValue = (kUSBStringDesc << 8) | index,
        .wIndex = 0x409, //English
        .wLength = sizeof(requestBuffer),
        .pData = requestBuffer
    };
    
    kern_return_t result;
    result = (*deviceInterface)->DeviceRequest(deviceInterface, &request);
    if (result != KERN_SUCCESS) {
        return nil;
    }
    
    int strLength = requestBuffer[0] - 2;
    CFStringRef serialNumberString = CFStringCreateWithBytes(kCFAllocatorDefault, &requestBuffer[2], strLength, kCFStringEncodingUTF16LE, false);
    return (__bridge NSString *)serialNumberString;
}

static int send_ctrl_msg(IOUSBDeviceInterface** dev, const UInt8 request, const UInt16 value, const UInt16 length)
{
    IOUSBDevRequest req;
    req.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    req.bRequest = request;
    req.wValue = value;
    req.wIndex = 0;
    req.wLength = length;
    req.pData = 0;
    req.wLenDone = 0;
    
    IOReturn rc = (*dev)->DeviceRequest(dev, &req);
    
    
    if(rc != kIOReturnSuccess)
    {
        return -1;
    }
    
    return req.wLenDone;
}
@end
