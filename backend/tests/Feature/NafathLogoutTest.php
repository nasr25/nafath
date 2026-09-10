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
        config(['nafath.logout_url' => 'https://www.iam.gov.sa/samlsso']);

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

    public function test_local_session_is_destroyed_on_logout(): void
    {
        $this->withSession(['some.state' => 'x'])->get('/_IAM/logout?slo=false');

        $this->assertGuest();
        $this->assertNull(session('some.state'));
    }
}
