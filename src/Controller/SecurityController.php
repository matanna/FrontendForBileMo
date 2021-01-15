<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

class SecurityController extends AbstractController
{
    /**
     * @Route("/login", name="app_login")
     */
    public function login(AuthenticationUtils $authenticationUtils, Session $session): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        $token = $session->get('token');

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername, 
            'error' => $error,
            'google_id' => $this->getParameter('app.google_id'),
            'redirect_uri' => $this->getParameter('app.redirect_uri'),
            'token' => $token
        ]);
    }

    /**
     * @Route("google/auth", name="google_auth")
     */
    public function googleAuth(Request $googleRequest, HttpClientInterface $client, Session $session)
    {
        $code = $googleRequest->query->get('code');
        
        $response = $client->request(
            'POST',
            'https://oauth2.googleapis.com/token?code=' .$code . '&client_id=' . $this->getParameter('app.google_id') .'&client_secret=' . $this->getParameter('app.google_secret') . '&redirect_uri=' . $this->getParameter('app.redirect_uri') . '&grant_type=authorization_code',
            [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Content-Length' => 0
                ]
            ]
        );

        $array= json_decode($response->getContent(), true);
        $token = $array['access_token'];
        
        $session->set('token', $token);
       
        return $this->redirectToRoute('app_login');
        
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
