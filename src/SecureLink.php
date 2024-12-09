<?php

namespace Minbash\Getsecure;

class SecureLink
{
    public static function generate(
        string $baselink,
        string $secret,
        int $period = 30
    ): string {
        if (!filter_var($baselink, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Invalid URL: $baselink");
        }

        $expires = time() + $period * 24 * 60 * 60;
        $urlPath = parse_url($baselink, PHP_URL_PATH);
        $hashString = $expires . $urlPath . " " . $secret;

        $hash = md5($hashString, true);
        $protectionString = rtrim(strtr(base64_encode($hash), "+/", "-_"), "=");

        return sprintf(
            "%s?md5=%s&expires=%d",
            $baselink,
            $protectionString,
            $expires
        );
    }
}
