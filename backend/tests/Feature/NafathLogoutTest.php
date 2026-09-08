<?php

namespace Tests\Feature;

use Tests\TestCase;

class NafathLogoutTest extends TestCase
{
    public function test_user_initiated_logout_sends_the_id_token_hint_to_iam(): void
    {
        config([
            'nafath.logout_mode'          => 'oidc',
            'nafath.logout_url'           => 'https://www.iam.gov.sa/oidc/logout',
            'nafath.post_logout_redirect' => '/',
        ]);

        $res = $this->withSession(['nafath.id_token' => 'EYJ.REAL.TOKEN'])->get('/_IAM/logout');

        $res->assertRedirect();
        $location = $res->headers->get('Location');
        $this->assertStringContainsString('id_token_hint=EYJ.REAL.TOKEN', $location);
        $this->assertStringContainsString('post_logout_redirect_uri=', $location);
    }

    public function test_iam_slo_dispatch_does_not_bounce_back_to_iam(): void
    {
        foreach (['false', 'False', '0'] as $slo) {
            $res = $this->get('/_IAM/logout?slo=' . $slo);
            $res->assertRedirect('/');
            $this->assertStringNotContainsString('iam.gov.sa', (string) $res->headers->get('Location'), "slo={$slo} bounced back to IAM");
        }
    }

    public function test_existing_query_string_on_the_logout_url_is_preserved(): void
    {
        config([
            'nafath.logout_mode' => 'slo',
            'nafath.logout_url'  => 'https://www.iam.gov.sa/samlsso?spEntityID=abc',
        ]);

        $res = $this->get('/_IAM/logout');

        $this->assertSame(
            'https://www.iam.gov.sa/samlsso?spEntityID=abc&slo=true',
            $res->headers->get('Location')
        );
    }
}
