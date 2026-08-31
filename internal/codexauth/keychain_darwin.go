//go:build darwin

package codexauth

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	securityFrameworkPath       = "/System/Library/Frameworks/Security.framework/Security"
	coreFoundationPath          = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
	cfStringEncodingUTF8        = 0x08000100
	errSecDuplicateItem   int32 = -25299
	errSecItemNotFound    int32 = -25300
	maximumMetadataSize         = 4096
)

type nativeKeychainClient struct{ api *keychainAPI }

type keychainAPI struct {
	secItemAdd          func(uintptr, uintptr) int32
	secItemCopyMatching func(uintptr, uintptr) int32
	secItemDelete       func(uintptr) int32
	secItemUpdate       func(uintptr, uintptr) int32

	dictionaryCreateMutable func(uintptr, int64, uintptr, uintptr) uintptr
	dictionarySetValue      func(uintptr, uintptr, uintptr)
	dictionaryGetValue      func(uintptr, uintptr) uintptr
	arrayGetCount           func(uintptr) int64
	arrayGetValueAtIndex    func(uintptr, int64) uintptr
	stringCreateWithBytes   func(uintptr, uintptr, int64, uint32, uint8) uintptr
	stringGetLength         func(uintptr) int64
	stringMaximumSize       func(int64, uint32) int64
	stringGetCString        func(uintptr, uintptr, int64, uint32) bool
	dataCreate              func(uintptr, uintptr, int64) uintptr
	dataGetLength           func(uintptr) int64
	dataGetBytePtr          func(uintptr) unsafe.Pointer
	getTypeID               func(uintptr) uintptr
	equal                   func(uintptr, uintptr) bool
	arrayGetTypeID          func() uintptr
	dictionaryGetTypeID     func() uintptr
	stringGetTypeID         func() uintptr
	dataGetTypeID           func() uintptr
	release                 func(uintptr)
	copyMemory              func(unsafe.Pointer, uintptr, uintptr) unsafe.Pointer

	secClass                                    uintptr
	secClassGenericPassword                     uintptr
	secAttrService                              uintptr
	secAttrAccount                              uintptr
	secAttrComment                              uintptr
	secAttrLabel                                uintptr
	secAttrAccessible                           uintptr
	secAttrAccessibleWhenUnlockedThisDeviceOnly uintptr
	secAttrSynchronizable                       uintptr
	secValueData                                uintptr
	secReturnAttributes                         uintptr
	secReturnData                               uintptr
	secMatchLimit                               uintptr
	secMatchLimitAll                            uintptr
	secMatchLimitOne                            uintptr
	secUseAuthenticationUI                      uintptr
	secUseAuthenticationUIFail                  uintptr
	cfBooleanTrue                               uintptr
	cfBooleanFalse                              uintptr
}

var loadedKeychainAPI struct {
	sync.Once
	api *keychainAPI
	err error
}

func newNativeKeychainClient() (keychainClient, error) {
	loadedKeychainAPI.Do(func() {
		loadedKeychainAPI.api, loadedKeychainAPI.err = loadKeychainAPI()
	})
	if loadedKeychainAPI.err != nil {
		return nil, loadedKeychainAPI.err
	}
	return &nativeKeychainClient{api: loadedKeychainAPI.api}, nil
}

func loadKeychainAPI() (*keychainAPI, error) {
	security, err := purego.Dlopen(securityFrameworkPath, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	coreFoundation, err := purego.Dlopen(coreFoundationPath, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	api := &keychainAPI{}
	purego.RegisterLibFunc(&api.secItemAdd, security, "SecItemAdd")
	purego.RegisterLibFunc(&api.secItemCopyMatching, security, "SecItemCopyMatching")
	purego.RegisterLibFunc(&api.secItemDelete, security, "SecItemDelete")
	purego.RegisterLibFunc(&api.secItemUpdate, security, "SecItemUpdate")
	purego.RegisterLibFunc(&api.dictionaryCreateMutable, coreFoundation, "CFDictionaryCreateMutable")
	purego.RegisterLibFunc(&api.dictionarySetValue, coreFoundation, "CFDictionarySetValue")
	purego.RegisterLibFunc(&api.dictionaryGetValue, coreFoundation, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&api.arrayGetCount, coreFoundation, "CFArrayGetCount")
	purego.RegisterLibFunc(&api.arrayGetValueAtIndex, coreFoundation, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&api.stringCreateWithBytes, coreFoundation, "CFStringCreateWithBytes")
	purego.RegisterLibFunc(&api.stringGetLength, coreFoundation, "CFStringGetLength")
	purego.RegisterLibFunc(&api.stringMaximumSize, coreFoundation, "CFStringGetMaximumSizeForEncoding")
	purego.RegisterLibFunc(&api.stringGetCString, coreFoundation, "CFStringGetCString")
	purego.RegisterLibFunc(&api.dataCreate, coreFoundation, "CFDataCreate")
	purego.RegisterLibFunc(&api.dataGetLength, coreFoundation, "CFDataGetLength")
	purego.RegisterLibFunc(&api.dataGetBytePtr, coreFoundation, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&api.getTypeID, coreFoundation, "CFGetTypeID")
	purego.RegisterLibFunc(&api.equal, coreFoundation, "CFEqual")
	purego.RegisterLibFunc(&api.arrayGetTypeID, coreFoundation, "CFArrayGetTypeID")
	purego.RegisterLibFunc(&api.dictionaryGetTypeID, coreFoundation, "CFDictionaryGetTypeID")
	purego.RegisterLibFunc(&api.stringGetTypeID, coreFoundation, "CFStringGetTypeID")
	purego.RegisterLibFunc(&api.dataGetTypeID, coreFoundation, "CFDataGetTypeID")
	purego.RegisterLibFunc(&api.release, coreFoundation, "CFRelease")
	purego.RegisterLibFunc(&api.copyMemory, purego.RTLD_DEFAULT, "memcpy")

	for destination, source := range map[*uintptr]struct {
		library uintptr
		name    string
	}{
		&api.secClass:                {security, "kSecClass"},
		&api.secClassGenericPassword: {security, "kSecClassGenericPassword"},
		&api.secAttrService:          {security, "kSecAttrService"},
		&api.secAttrAccount:          {security, "kSecAttrAccount"},
		&api.secAttrComment:          {security, "kSecAttrComment"},
		&api.secAttrLabel:            {security, "kSecAttrLabel"},
		&api.secAttrAccessible:       {security, "kSecAttrAccessible"},
		&api.secAttrAccessibleWhenUnlockedThisDeviceOnly: {security, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"},
		&api.secAttrSynchronizable:                       {security, "kSecAttrSynchronizable"},
		&api.secValueData:                                {security, "kSecValueData"},
		&api.secReturnAttributes:                         {security, "kSecReturnAttributes"},
		&api.secReturnData:                               {security, "kSecReturnData"},
		&api.secMatchLimit:                               {security, "kSecMatchLimit"},
		&api.secMatchLimitAll:                            {security, "kSecMatchLimitAll"},
		&api.secMatchLimitOne:                            {security, "kSecMatchLimitOne"},
		&api.secUseAuthenticationUI:                      {security, "kSecUseAuthenticationUI"},
		&api.secUseAuthenticationUIFail:                  {security, "kSecUseAuthenticationUIFail"},
		&api.cfBooleanTrue:                               {coreFoundation, "kCFBooleanTrue"},
		&api.cfBooleanFalse:                              {coreFoundation, "kCFBooleanFalse"},
	} {
		value, err := loadCFReference(api.copyMemory, source.library, source.name)
		if err != nil {
			return nil, err
		}
		*destination = value
	}
	return api, nil
}

func loadCFReference(
	copyMemory func(unsafe.Pointer, uintptr, uintptr) unsafe.Pointer,
	library uintptr,
	name string,
) (uintptr, error) {
	symbol, err := purego.Dlsym(library, name)
	if err != nil || symbol == 0 {
		return 0, errors.New("load Keychain framework")
	}
	// Dlsym returns the stable address of a C global whose value is a
	// CoreFoundation reference. Copying its pointer-sized value through libc
	// avoids treating a C address as a Go pointer. The loaded framework outlives
	// this process.
	var value uintptr
	if copyMemory(unsafe.Pointer(&value), symbol, unsafe.Sizeof(value)) == nil {
		return 0, errors.New("load Keychain framework")
	}
	runtime.KeepAlive(&value)
	if value == 0 {
		return 0, errors.New("load Keychain framework")
	}
	return value, nil
}

func (client *nativeKeychainClient) Add(service, account, comment string, secret []byte) error {
	if len(secret) == 0 || len(secret) > maximumKeychainRecordSize {
		return ErrProviderUnavailable
	}
	query, cleanup, err := client.api.newQuery()
	if err != nil {
		return ErrProviderUnavailable
	}
	defer cleanup()
	if err := query.setString(client.api, client.api.secAttrService, service); err != nil {
		return ErrProviderUnavailable
	}
	if err := query.setString(client.api, client.api.secAttrAccount, account); err != nil {
		return ErrProviderUnavailable
	}
	if err := query.setString(client.api, client.api.secAttrComment, comment); err != nil {
		return ErrProviderUnavailable
	}
	if err := query.setString(client.api, client.api.secAttrLabel, "ACS Codex authentication: "+account); err != nil {
		return ErrProviderUnavailable
	}
	client.api.dictionarySetValue(query.dictionary, client.api.secAttrAccessible, client.api.secAttrAccessibleWhenUnlockedThisDeviceOnly)
	client.api.dictionarySetValue(query.dictionary, client.api.secAttrSynchronizable, client.api.cfBooleanFalse)
	if err := query.setData(client.api, client.api.secValueData, secret); err != nil {
		return ErrProviderUnavailable
	}
	status := client.api.secItemAdd(query.dictionary, 0)
	runtime.KeepAlive(secret)
	switch status {
	case 0:
		return nil
	case errSecDuplicateItem:
		return ErrIdentityExists
	default:
		return ErrProviderUnavailable
	}
}

func (client *nativeKeychainClient) Update(service, account, comment string, secret []byte) error {
	if len(secret) == 0 || len(secret) > maximumKeychainRecordSize {
		return ErrProviderUnavailable
	}
	query, cleanupQuery, err := client.api.newQuery()
	if err != nil {
		return ErrProviderUnavailable
	}
	defer cleanupQuery()
	if err := query.setString(client.api, client.api.secAttrService, service); err != nil {
		return ErrProviderUnavailable
	}
	if err := query.setString(client.api, client.api.secAttrAccount, account); err != nil {
		return ErrProviderUnavailable
	}

	updates, cleanupUpdates, err := client.api.newDictionary()
	if err != nil {
		return ErrProviderUnavailable
	}
	defer cleanupUpdates()
	if err := updates.setString(client.api, client.api.secAttrComment, comment); err != nil {
		return ErrProviderUnavailable
	}
	if err := updates.setData(client.api, client.api.secValueData, secret); err != nil {
		return ErrProviderUnavailable
	}
	status := client.api.secItemUpdate(query.dictionary, updates.dictionary)
	runtime.KeepAlive(secret)
	if status != 0 {
		return ErrProviderUnavailable
	}
	return nil
}

func (client *nativeKeychainClient) Attributes(service string, account *string) ([]keychainAttributes, error) {
	query, cleanup, err := client.api.newQuery()
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	defer cleanup()
	if err := query.setString(client.api, client.api.secAttrService, service); err != nil {
		return nil, ErrProviderUnavailable
	}
	if account != nil {
		if err := query.setString(client.api, client.api.secAttrAccount, *account); err != nil {
			return nil, ErrProviderUnavailable
		}
	}
	client.api.dictionarySetValue(query.dictionary, client.api.secReturnAttributes, client.api.cfBooleanTrue)
	client.api.dictionarySetValue(query.dictionary, client.api.secMatchLimit, client.api.secMatchLimitAll)

	var result uintptr
	status := client.api.secItemCopyMatching(query.dictionary, uintptr(unsafe.Pointer(&result)))
	if status == errSecItemNotFound {
		return nil, errKeychainItemNotFound
	}
	if status != 0 || result == 0 {
		return nil, ErrProviderUnavailable
	}
	defer client.api.release(result)
	return client.api.decodeAttributeResult(result)
}

func (client *nativeKeychainClient) Data(service, account string) ([]byte, error) {
	query, cleanup, err := client.api.newQuery()
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	defer cleanup()
	if err := query.setString(client.api, client.api.secAttrService, service); err != nil {
		return nil, ErrProviderUnavailable
	}
	if err := query.setString(client.api, client.api.secAttrAccount, account); err != nil {
		return nil, ErrProviderUnavailable
	}
	client.api.dictionarySetValue(query.dictionary, client.api.secReturnData, client.api.cfBooleanTrue)
	client.api.dictionarySetValue(query.dictionary, client.api.secMatchLimit, client.api.secMatchLimitOne)

	var result uintptr
	status := client.api.secItemCopyMatching(query.dictionary, uintptr(unsafe.Pointer(&result)))
	if status == errSecItemNotFound {
		return nil, errKeychainItemNotFound
	}
	if status != 0 || result == 0 || client.api.getTypeID(result) != client.api.dataGetTypeID() {
		return nil, ErrProviderUnavailable
	}
	defer client.api.release(result)
	length := client.api.dataGetLength(result)
	if length <= 0 || length > maximumKeychainRecordSize {
		return nil, ErrProviderUnavailable
	}
	pointer := client.api.dataGetBytePtr(result)
	if pointer == nil {
		return nil, ErrProviderUnavailable
	}
	// CFDataGetBytePtr points into result, which remains retained until the
	// returned bytes have been copied into Go-owned memory below.
	return append([]byte(nil), unsafe.Slice((*byte)(pointer), int(length))...), nil
}

func (client *nativeKeychainClient) Delete(service, account string) error {
	query, cleanup, err := client.api.newQuery()
	if err != nil {
		return ErrProviderUnavailable
	}
	defer cleanup()
	if err := query.setString(client.api, client.api.secAttrService, service); err != nil {
		return ErrProviderUnavailable
	}
	if err := query.setString(client.api, client.api.secAttrAccount, account); err != nil {
		return ErrProviderUnavailable
	}
	status := client.api.secItemDelete(query.dictionary)
	if status == errSecItemNotFound {
		return errKeychainItemNotFound
	}
	if status != 0 {
		return ErrProviderUnavailable
	}
	return nil
}

type cfQuery struct {
	dictionary uintptr
	values     []uintptr
}

func (api *keychainAPI) newQuery() (*cfQuery, func(), error) {
	query, cleanup, err := api.newDictionary()
	if err != nil {
		return nil, func() {}, err
	}
	api.configureQuery(query.dictionary)
	return query, cleanup, nil
}

func (api *keychainAPI) configureQuery(dictionary uintptr) {
	api.dictionarySetValue(dictionary, api.secClass, api.secClassGenericPassword)
	api.dictionarySetValue(dictionary, api.secUseAuthenticationUI, api.secUseAuthenticationUIFail)
}

func (api *keychainAPI) newDictionary() (*cfQuery, func(), error) {
	dictionary := api.dictionaryCreateMutable(0, 0, 0, 0)
	if dictionary == 0 {
		return nil, func() {}, ErrProviderUnavailable
	}
	query := &cfQuery{dictionary: dictionary}
	cleanup := func() {
		for _, value := range query.values {
			api.release(value)
		}
		api.release(dictionary)
	}
	return query, cleanup, nil
}

func (query *cfQuery) setString(api *keychainAPI, key uintptr, value string) error {
	contents := []byte(value)
	if len(contents) == 0 {
		return ErrProviderUnavailable
	}
	reference := api.stringCreateWithBytes(
		0, uintptr(unsafe.Pointer(&contents[0])), int64(len(contents)), cfStringEncodingUTF8, 0,
	)
	runtime.KeepAlive(contents)
	if reference == 0 {
		return ErrProviderUnavailable
	}
	query.values = append(query.values, reference)
	api.dictionarySetValue(query.dictionary, key, reference)
	return nil
}

func (query *cfQuery) setData(api *keychainAPI, key uintptr, value []byte) error {
	if len(value) == 0 {
		return ErrProviderUnavailable
	}
	reference := api.dataCreate(0, uintptr(unsafe.Pointer(&value[0])), int64(len(value)))
	runtime.KeepAlive(value)
	if reference == 0 {
		return ErrProviderUnavailable
	}
	query.values = append(query.values, reference)
	api.dictionarySetValue(query.dictionary, key, reference)
	return nil
}

func (api *keychainAPI) decodeAttributeResult(result uintptr) ([]keychainAttributes, error) {
	switch api.getTypeID(result) {
	case api.arrayGetTypeID():
		count := api.arrayGetCount(result)
		if count < 0 || count > 10000 {
			return nil, ErrProviderUnavailable
		}
		attributes := make([]keychainAttributes, 0, count)
		for index := int64(0); index < count; index++ {
			decoded, err := api.decodeAttributes(api.arrayGetValueAtIndex(result, index))
			if err != nil {
				return nil, err
			}
			attributes = append(attributes, decoded)
		}
		return attributes, nil
	case api.dictionaryGetTypeID():
		decoded, err := api.decodeAttributes(result)
		if err != nil {
			return nil, err
		}
		return []keychainAttributes{decoded}, nil
	default:
		return nil, ErrProviderUnavailable
	}
}

func (api *keychainAPI) decodeAttributes(dictionary uintptr) (keychainAttributes, error) {
	if dictionary == 0 || api.getTypeID(dictionary) != api.dictionaryGetTypeID() {
		return keychainAttributes{}, ErrProviderUnavailable
	}
	account, err := api.goString(api.dictionaryGetValue(dictionary, api.secAttrAccount))
	if err != nil {
		return keychainAttributes{}, err
	}
	comment, err := api.goString(api.dictionaryGetValue(dictionary, api.secAttrComment))
	if err != nil {
		return keychainAttributes{}, err
	}
	accessible := ""
	if reference := api.dictionaryGetValue(dictionary, api.secAttrAccessible); reference != 0 {
		var err error
		accessible, err = api.goString(reference)
		if err != nil {
			return keychainAttributes{}, err
		}
	}
	synchronizable := false
	if reference := api.dictionaryGetValue(dictionary, api.secAttrSynchronizable); reference != 0 {
		switch {
		case api.equal(reference, api.cfBooleanFalse):
		case api.equal(reference, api.cfBooleanTrue):
			synchronizable = true
		default:
			return keychainAttributes{}, ErrProviderUnavailable
		}
	}
	return keychainAttributes{
		Account: account, Comment: comment, Accessible: accessible, Synchronizable: synchronizable,
	}, nil
}

func (api *keychainAPI) goString(reference uintptr) (string, error) {
	if reference == 0 || api.getTypeID(reference) != api.stringGetTypeID() {
		return "", ErrProviderUnavailable
	}
	length := api.stringGetLength(reference)
	maximum := api.stringMaximumSize(length, cfStringEncodingUTF8)
	if length <= 0 || maximum <= 0 || maximum > maximumMetadataSize {
		return "", ErrProviderUnavailable
	}
	buffer := make([]byte, maximum+1)
	if !api.stringGetCString(reference, uintptr(unsafe.Pointer(&buffer[0])), int64(len(buffer)), cfStringEncodingUTF8) {
		return "", ErrProviderUnavailable
	}
	for index, value := range buffer {
		if value == 0 {
			return string(buffer[:index]), nil
		}
	}
	return "", ErrProviderUnavailable
}
