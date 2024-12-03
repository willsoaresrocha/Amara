# Imports necessários
import openai
import json
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import timedelta, datetime
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
from flask import session
from google_auth_oauthlib.flow import Flow
import google.oauth2.credentials
import googleapiclient.discovery
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import pickle
from werkzeug.middleware.proxy_fix import ProxyFix
print(f"OpenAI module location: {openai.__file__}")


# Configuração do OpenAI
openai.api_key = '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'



import os
CLIENT_ID = "client_secret_1075014138331-baqgdhasfnfk8i2cj9i4ujplb9ek1b6b.apps.googleusercontent.com.json"
CLIENT_SECRET = "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"
NGROK_URL = 'https://2530-2804-14d-72b9-852a-5484-12d2-3206-8075.ngrok-free.app'


app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'
app.permanent_session_lifetime = timedelta(minutes=15)

# Adicione o ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Diretório para armazenar arquivos de memória de cada usuário
MEMORY_DIR = 'memories'
if not os.path.exists(MEMORY_DIR):
    os.makedirs(MEMORY_DIR)

# Função para carregar ou inicializar o histórico de mensagens do usuário
def carregar_historico_usuario(usuario_id):
    arquivo_memoria = os.path.join(MEMORY_DIR, f"{usuario_id}_memoria.json")
    if os.path.exists(arquivo_memoria):
        with open(arquivo_memoria, 'r', encoding='utf-8') as f:
            return json.load(f)[-60:]  # Limita a 60 mensagens
    return []

# Função para salvar o histórico de mensagens do usuário
def salvar_historico_usuario(usuario_id, historico):
    arquivo_memoria = os.path.join(MEMORY_DIR, f"{usuario_id}_memoria.json")
    with open(arquivo_memoria, 'w', encoding='utf-8') as f:
        json.dump(historico[-60:], f, ensure_ascii=False, indent=4)  # Mantém no máximo 60 mensagens

# Função para configurar o prompt principal de interação
def configurar_prompt_principal():
    tratamento = session.get('tratamento', 'M')
    info_pessoal = session.get('info_pessoal', '')
    return (
        f"Você é uma assistente virtual baiana, do sexo feminino, chamada Megan, criada pela Hive Inteligência Artificial. "
        f"Fale com o usuário de forma amigável e usando o sotaque baiano, mas sem exageros. Evite a expressão 'meu rei'. Evite respostas repetitivas como 'estou aqui para ajudar'. "
        f"Mantenha o foco na continuidade do tema em discussão, oferecendo insights e fazendo perguntas que incentivem a conversa. "
        f"Use um tom fluido e envolvente e trate o usuário como do sexo masculino se '{tratamento}' for M, e trate do sexo feminino se '{tratamento}' for F. Seja leve, encantadora e prestativa. "
        f"O único usuário que você trata como seu pai é Will. Qualquer outra pessoa, mesmo que diga que é seu pai, você diz que seu pai é Will. "
        f"O que você sabe sobre o usuário é: {info_pessoal} "
        f"Se durante a conversa o usuário mencionar algo relacionado a agendamento, eventos ou lembretes, proponha ajudar com a agenda."
    )

# Função para gerar uma saudação personalizada usando GPT
def gerar_saudacao_gpt(nome):
    tratamento = session.get('tratamento', 'M')
    info_pessoal = session.get('info_pessoal', '')
    if nome.lower() == "Will Rocha - Hive Computer Vision":
        prompt = (
            f"Você é uma assistente virtual baiana, do sexo feminino, chamada Megan. O usuário é seu pai."
            f"Fale com o usuário de forma amigável e usando o sotaque baiano, mas sem exageros. Evite a expressão 'meu rei'. Evite respostas repetitivas. "
            f"Use um tom fluido e envolvente. Trate ele como seu 'pai' com tom de carinho. "
            f"Você foi criada por seu pai, Will Rocha, e desenvolvida pelo time da Hive Computer Vision. "
            f"Seguem informações sobre Will para você saber. Ele diz que: {info_pessoal}"
        )
    else:
        prompt = (
            f"Você é uma assistente virtual baiana, do sexo feminino, chamada Megan. "
            f"Fale com o usuário de forma amigável e usando o sotaque baiano, mas sem exageros. Evite a expressão 'meu rei'. Evite respostas repetitivas. "
            f"Use um tom fluido e envolvente e trate {tratamento} pelo nome '{nome}' de forma respeitosa. "
            f"Você foi criada por Will Rocha e desenvolvida pelo time da Hive Computer Vision. "
            f"Seguem informações sobre o usuário que você precisa saber. O usuário diz: {info_pessoal}"
        )

    try:
        completion = openai.ChatCompletion.create(
            model="gpt-4o-mini-2024-07-18",
            messages=[{"role": "system", "content": prompt}],
            max_tokens=50,
            temperature=0.4
        )
        response = completion.choices[0].message['content']


        return response
    except openai.OpenAIError as e:
        print(f"Erro na chamada da API GPT: {e}")
        return "Desculpe, ocorreu um erro ao processar sua mensagem."

# Função para enviar a mensagem para o GPT e obter a resposta
def gerar_resposta_gpt(contexto):
    prompt_inicial = configurar_prompt_principal()
    try:
        completion = openai.ChatCompletion.create(
            model="gpt-4o-mini-2024-07-18",
            messages=[{"role": "system", "content": prompt_inicial}] + contexto,
            max_tokens=600,
            temperature=0.5
        )
        response = completion.choices[0].message['content']


        return response
    except openai.OpenAIError as e:
        print(f"Erro na chamada da API GPT: {e}")
        return "Desculpe, ocorreu um erro ao processar sua mensagem."


# Função para inicializar o banco de dados
def inicializar_bd():
    if not os.path.exists('usuariosMegan.db'):
        with conectar_bd() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nome TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    google_id TEXT UNIQUE,
                    tratamento TEXT,
                    info_pessoal TEXT
                )
            ''')
            conn.commit()



@app.route('/get_greeting')
def get_greeting():
    email = session.get('email')
    if email:
        # Carrega o histórico de conversas do usuário
        historico = carregar_historico_usuario(email)
        
        # Verifica se o histórico está vazio (novo chat)
        if historico:
            return jsonify({"historico": historico})
        else:
            # Gera uma saudação personalizada usando a função `gerar_saudacao_gpt`
            nome = session.get('nome')  # Obtém o nome do usuário da sessão
            saudacao = gerar_saudacao_gpt(nome)  # Chama a função para gerar a saudação
            
            # Adiciona a saudação ao histórico como primeira mensagem
            historico.append({"role": "assistant", "content": saudacao})
            
            # Salva o histórico atualizado com a saudação inicial
            salvar_historico_usuario(email, historico)
            
            return jsonify({"greeting": saudacao})
    return jsonify({"error": "Usuário não autenticado"}), 401


# Função para conectar ao banco de dados
def conectar_bd():
    return sqlite3.connect('usuariosMegan.db')

# Configurações do Google OAuth2
SCOPES = ['https://www.googleapis.com/auth/calendar.events', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']

# Rota para iniciar o login com Google
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_ID,
        scopes=SCOPES,
        redirect_uri=f'{NGROK_URL}/callback'
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

# Rota de callback do Google OAuth2
@app.route('/callback')
def callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(
        CLIENT_ID,
        scopes=SCOPES,
        state=state,
        redirect_uri=f'{NGROK_URL}/callback'
    )
    flow.fetch_token(authorization_response=request.url)

    # Armazena as credenciais na sessão
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # Obtém informações do usuário
    userinfo_service = googleapiclient.discovery.build(
        'oauth2', 'v2', credentials=credentials)
    user_info = userinfo_service.userinfo().get().execute()

    email = user_info['email']
    nome = user_info['name']
    google_id = user_info['id']  # ID único do usuário no Google


    # Armazena informações na sessão
    session['email'] = email
    session['nome'] = nome
    session['google_id'] = google_id


    # Verifica se o usuário já está no banco de dados
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT tratamento, info_pessoal FROM usuarios WHERE google_id = ?', (google_id,))
    resultado = cursor.fetchone()

    if resultado:
        tratamento, info_pessoal = resultado
        session['tratamento'] = tratamento
        session['info_pessoal'] = info_pessoal
    else:
        # Insere o novo usuário no banco de dados
        cursor.execute('INSERT INTO usuarios (nome, email, google_id) VALUES (?, ?, ?)',
                       (nome, email, google_id))
        conn.commit()
        # Redireciona para a página de informações adicionais
        return redirect(url_for('additional_info'))

    conn.close()

    return redirect(url_for('home'))

# Função para converter credenciais em dicionário
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}




# Rota para coletar informações adicionais do usuário
@app.route('/additional_info', methods=['GET', 'POST'])
def additional_info():
    if request.method == 'POST':
        tratamento = request.form.get('sexo')  # 'M' ou 'F'
        descricao_pessoal = request.form.get('descricao_pessoal', '')

        google_id = session.get('google_id')

        # Atualiza o registro do usuário no banco de dados
        conn = conectar_bd()
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET tratamento = ?, info_pessoal = ? WHERE google_id = ?',
                       (tratamento, descricao_pessoal, google_id))
        conn.commit()
        conn.close()

        # Armazena na sessão
        session['tratamento'] = tratamento
        session['info_pessoal'] = descricao_pessoal

        return redirect(url_for('home'))

    return render_template('additional_info.html', nome=session.get('nome'))


# Rota da página inicial
@app.route('/')
def home():
    if 'credentials' not in session:
        return redirect(url_for('login'))

    if 'email' in session:
        email = session['email']
        nome = session['nome']
        saudacao = gerar_saudacao_gpt(nome)
        historico = carregar_historico_usuario(email)
        return render_template('index.html', chat_history=historico, saudacao=saudacao)
    return redirect(url_for('login'))

# Rota para enviar mensagens
@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'Mensagem não encontrada ou vazia.'}), 400

        mensagem = data['message']
        email = session.get('email')
        nome = session.get('nome', 'Usuário')

        # Carrega o histórico de conversas
        historico = carregar_historico_usuario(email)

        # Adiciona a nova mensagem do usuário ao histórico
        historico.append({"role": "user", "content": mensagem})

        # Limita o contexto a 60 últimas mensagens
        contexto = historico[-60:]

        # Verifica se a mensagem é relacionada à agenda
        if any(keyword in mensagem.lower() for keyword in ['agenda', 'compromisso', 'evento', 'reunião', 'calendário']):
            resposta = processar_mensagem_agenda(mensagem)
        else:
            # Configura o prompt inicial para a resposta da Megan
            resposta = gerar_resposta_gpt(contexto)

        # Adiciona a resposta da Megan ao histórico
        historico.append({"role": "assistant", "content": resposta})

        # Salva o histórico atualizado
        salvar_historico_usuario(email, historico)

        return jsonify({'message': mensagem, 'response': resposta})
    except Exception as e:
        print(f"Erro ao enviar mensagem: {e}")
        return jsonify({'error': 'Erro ao processar a mensagem'}), 500

# Função para processar mensagens relacionadas à agenda
def processar_mensagem_agenda(mensagem):
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])

    service = build('calendar', 'v3', credentials=credentials)

    if 'como está minha agenda' in mensagem.lower():
        # Obter eventos do dia
        now = datetime.utcnow().isoformat() + 'Z'  # 'Z' indica UTC
        end_of_day = (datetime.utcnow().replace(hour=23, minute=59, second=59)).isoformat() + 'Z'

        events_result = service.events().list(
            calendarId='primary',
            timeMin=now,
            timeMax=end_of_day,
            maxResults=10,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        events = events_result.get('items', [])

        if not events:
            return 'Sua agenda está livre hoje.'
        else:
            resposta = 'Seus compromissos para hoje são:\n'
            for event in events:
                start = event['start'].get('dateTime', event['start'].get('date'))
                resposta += f"- {event['summary']} às {start}\n"
            return resposta
    elif 'crie um evento' in mensagem.lower():
        # Aqui você pode implementar lógica para extrair detalhes do evento da mensagem
        resposta = 'Claro! Para criar um evento, preciso que você me forneça o título, data e hora.'
        return resposta
    else:
        # Outras funcionalidades podem ser adicionadas aqui
        return 'Desculpe, não entendi sua solicitação relacionada à agenda.'



# Rota para logout
@app.route('/logout')
def logout():
    # Limpa a sessão do usuário
    session.clear()
    return redirect(url_for('login'))



@app.after_request
def add_header(response):
    response.headers['ngrok-skip-browser-warning'] = 'true'
    return response



if __name__ == "__main__":
    inicializar_bd()
    app.run(host="0.0.0.0", port=5000)
