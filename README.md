# discord-username

gets discord usernames from memory without needing to update offsets every time discord updates

## how it works

instead of using pointer chains and static offsets (which break constantly), this just scans discord's memory for the pattern `"username":"` and grabs whatever's between the quotes

works for:
- your username
- friends in dms
- pretty much any username that appears in discord's ui

## usage

```cpp
auto memory = std::make_shared<c_memory>("Discord.exe");
std::string username = memory->find_username();
std::cout << username << std::endl;
```

that's it. no messing with cheat engine or updating offsets

## why i made this

the original method (the one with pointer chains) is cool but annoying to maintain. every time discord updates you gotta rescan and find new offsets. this just scans at runtime and always finds the username

## credits

got the idea from [vmpprotect/discord-username-memory](https://github.com/vmpprotect/discord-username-memory) but changed it to use pattern scanning instead of hardcoded offsets

## disclaimer

educational use only. don't be dumb with it
