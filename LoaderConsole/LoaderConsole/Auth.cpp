#include "Auth.hpp"

void KeyAuth::api::ban(std::string reason)
{
}

void KeyAuth::api::init()
{
}

void KeyAuth::api::check()
{
}

void KeyAuth::api::log(std::string msg)
{
}

void KeyAuth::api::license(std::string key)
{
}

std::string KeyAuth::api::var(std::string varid)
{
	return std::string();
}

std::string KeyAuth::api::webhook(std::string id, std::string params, std::string body, std::string contenttype)
{
	return std::string();
}

void KeyAuth::api::setvar(std::string var, std::string vardata)
{
}

std::string KeyAuth::api::getvar(std::string var)
{
	return std::string();
}

bool KeyAuth::api::checkblack()
{
	return false;
}

void KeyAuth::api::web_login()
{
}

void KeyAuth::api::button(std::string value)
{
}

void KeyAuth::api::upgrade(std::string username, std::string key)
{
}

void KeyAuth::api::login(std::string username, std::string password)
{
}

std::vector<unsigned char> KeyAuth::api::download(std::string fileid)
{
	return std::vector<unsigned char>();
}

void KeyAuth::api::regstr(std::string username, std::string password, std::string key, std::string email)
{
}

void KeyAuth::api::chatget(std::string channel)
{
}

bool KeyAuth::api::chatsend(std::string message, std::string channel)
{
	return false;
}

void KeyAuth::api::changeusername(std::string newusername)
{
}

std::string KeyAuth::api::fetchonline()
{
	return std::string();
}

void KeyAuth::api::forgot(std::string username, std::string email)
{
}
