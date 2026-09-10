<?php

namespace Tests\Feature;

use Tests\TestCase;

/**
 * Logout per the NAFATH Authentication Service Integration Guide v3.3, §2.2.2
 * "Direct Logout (Applicable in SAML2 and OIDC)":
 *   INPUT:  https://www.iam.gov.sa/samlsso?slo=true
 *   OUTPUT: https://serviceprovider.com.sa/logout?slo=false
 */
class NafathLogoutTest extends TestCase
{
    public function test_user_initiated_logout_redirects_to_iam_with_slo_true(): void
    {
        config([
            'nafath.logout_return' => 'dispatch',
            'nafath.logout_url'    => 'https://www.iam.gov.sa/samlsso',
        ]);

        $this->get('/_IAM/logout')
            ->assertRedirect('https://www.iam.gov.sa/samlsso?slo=true');
    }

    public function test_iam_dispatch_lands_on_the_public_page_with_a_confirmation(): void
    {
        // IAM calls the SP's registered logout URL with ?slo=false (§2.2.1 step 6.1).
        config(['nafath.post_logout_redirect' => '/']);

        $this->get('/_IAM/logout?slo=false')
            ->assertRedirect('/?logged_out=1');
    }

    public function test_confirmation_flag_is_merged_into_an_existing_query(): void
    {
        config(['nafath.post_logout_redirect' => '/home?lang=ar']);

        $this->get('/_IAM/logout?slo=false')
            ->assertRedirect('/home?lang=ar&logged_out=1');
    }

    public function test_public_page_shows_the_message_only_when_flagged(): void
    {
        $this->get('/?logged_out=1')
            ->assertSee('signed out of NAFATH successfully', false);

        $this->get('/')
            ->assertDontSee('signed out of NAFATH successfully', false);
    }

    public function test_redirect_target_may_be_a_link_to_another_system(): void
    {
        config(['nafath.post_logout_redirect' => 'https://mysystem.gov.sa/home']);

        $this->get('/_IAM/logout?slo=false')
            ->assertRedirect('https://mysystem.gov.sa/home?logged_out=1');
    }

    public function test_link_keeps_its_own_query_parameters(): void
    {
        config(['nafath.post_logout_redirect' => 'https://mysystem.gov.sa/home?lang=ar']);

        $this->get('/_IAM/logout?slo=false')
            ->assertRedirect('https://mysystem.gov.sa/home?lang=ar&logged_out=1');
    }

    public function test_direct_mode_keeps_the_user_in_our_system(): void
    {
        config([
            'nafath.logout_return'        => 'direct',
            'nafath.logout_url'           => 'https://www.iam.gov.sa/samlsso',
            'nafath.post_logout_redirect' => 'https://mysystem.gov.sa/home',
        ]);

        $res = $this->get('/_IAM/logout');

        $res->assertOk();
        // IAM logout is requested by the browser, not by a redirect away.
        $res->assertSee('https://www.iam.gov.sa/samlsso?slo=true', false);
        // …and we send the user on ourselves.
        $res->assertSee('https:\/\/mysystem.gov.sa\/home?logged_out=1', false);
    }

    public function test_dispatch_mode_redirects_the_browser_to_iam(): void
    {
        config([
            'nafath.logout_return' => 'dispatch',
            'nafath.logout_url'    => 'https://www.iam.gov.sa/samlsso',
        ]);

        $this->get('/_IAM/logout')
            ->assertRedirect('https://www.iam.gov.sa/samlsso?slo=true');
    }

    public function test_local_session_is_destroyed_on_logout(): void
    {
        $this->withSession(['some.state' => 'x'])->get('/_IAM/logout?slo=false');

        $this->assertGuest();
        $this->assertNull(session('some.state'));
    }
}
