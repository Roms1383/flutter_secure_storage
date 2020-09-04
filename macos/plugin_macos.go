package flutter_secure_storage

import (
	flutter "github.com/go-flutter-desktop/go-flutter"
	"github.com/go-flutter-desktop/go-flutter/plugin"
	"github.com/keybase/go-keychain"
	"log"
)

// FlutterSecureStoragePlugin implements flutter.Plugin and handles method.
type FlutterSecureStoragePlugin struct{}

var _ flutter.Plugin = &FlutterSecureStoragePlugin{} // compile-time type check

const service string = "flutter_secure_storage";
const access_group string = "plugins.it_nomads.com/flutter_secure_storage";

// InitPlugin initializes the plugin.
func (p *FlutterSecureStoragePlugin) InitPlugin(messenger plugin.BinaryMessenger) error {
	channel := plugin.NewMethodChannel(messenger, "plugins.it_nomads.com/flutter_secure_storage", plugin.StandardMethodCodec{})
	channel.HandleFunc("containsKey", p.containsKey)
	channel.HandleFunc("read", p.read)
	channel.HandleFunc("readAll", p.readAll)
	channel.HandleFunc("write", p.write)
	channel.HandleFunc("delete", p.delete)

	return nil
}


func (p *FlutterSecureStoragePlugin) containsKey(arguments interface{}) (reply interface{}, err error) {
	key := arguments.(map[interface{}]interface{})["key"].(string)
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(key)
	item.SetAccessGroup(access_group)
	item.SetMatchLimit(keychain.MatchLimitOne)
	item.SetAccessible(keychain.AccessibleAfterFirstUnlock)
	item.SetReturnAttributes(true)
	item.SetReturnData(false)
	results, err := keychain.QueryItem(item)
	log.Printf("containsKey results: %v", results)
	log.Printf("containsKey len(results): %v", len(results))
	log.Printf("containsKey err: %v", err)
	return results != nil && len(results) == 1, err
}

func (p *FlutterSecureStoragePlugin) read(arguments interface{}) (reply interface{}, err error) {
	key := arguments.(map[interface{}]interface{})["key"].(string)
	log.Printf("read key: %v", key)
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(key)
	item.SetAccessGroup(access_group)
	item.SetMatchLimit(keychain.MatchLimitOne)
	item.SetAccessible(keychain.AccessibleAfterFirstUnlock)
	item.SetReturnAttributes(true)
	item.SetReturnData(true)
	results, err := keychain.QueryItem(item)
	if err != nil {
		return nil, err
	} else {
		log.Printf("readAll results: %v", results)
		for _, v := range results {
			return string(v.Data), nil
		}
		return nil, nil
	}
}

func (p *FlutterSecureStoragePlugin) readAll(arguments interface{}) (reply interface{}, err error) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccessGroup(access_group)
	item.SetMatchLimit(keychain.MatchLimitAll)
	item.SetAccessible(keychain.AccessibleAfterFirstUnlock)
	item.SetReturnAttributes(true)
	results, err := keychain.QueryItem(item)
	if err != nil {
		return nil, err
	} else {
		var outputs = make(map[interface{}]interface{})
		for _, v := range results {
			log.Printf("readAll v: %v", v)
			args := make(map[interface{}]interface{})
			args["key"] = string(v.Account)
			var value, _ = p.read(args)
			log.Printf("readAll value: %v", value)
			outputs[v.Account] = value
		}
		log.Printf("readAll outputs: %v", outputs)
		return outputs, nil
	}
}

func (p *FlutterSecureStoragePlugin) write(arguments interface{}) (reply interface{}, err error) {
	key := arguments.(map[interface{}]interface{})["key"].(string)
	value := arguments.(map[interface{}]interface{})["value"].(string)
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(key)
	item.SetLabel("Flutter Secure Storage")
	item.SetAccessGroup(access_group)
	item.SetData([]byte(value))
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleAfterFirstUnlock)
	raw, _ := p.containsKey(map[interface{}]interface{}{"key":key})
	found := raw.(bool)
	log.Printf("found: %v", found)
	var e error
	if found {
		e = keychain.UpdateItem(item, item)
	} else {
		e = keychain.AddItem(item)
	}
	if e != nil {
		// Duplicate
		return nil, e
	} else {
		if found {
			return "updated successfully", nil
		} else {
			return "added successfully", nil
		}
	}
}

func (p *FlutterSecureStoragePlugin) delete(arguments interface{}) (reply interface{}, err error) {
	key := arguments.(map[interface{}]interface{})["key"].(string)
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(key)
	item.SetAccessGroup(access_group)
	e := keychain.DeleteItem(item)
	if e != nil {
		return nil, e
	} else {
		return "deleted successfully", nil
	}
}
